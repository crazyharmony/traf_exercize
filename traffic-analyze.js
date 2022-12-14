const fs = require("fs");
const util = require('util');
const {ArgumentParser, PARSER} = require('argparse');
const CsvParser = require('csv-parser');
const IpPortParser = require('parse-ip-port');

const default_infile = 'traf.txt';
const field_delimiter = ';';
const headers = ['src_ip_port', 'src_mac', 'dst_ip_port', 'dst_mac', 'is_udp', 'data_size', 'time_interval'];

const top_nodes_list_size = 10;
const top_networks_list_size = 10;

const ap = new ArgumentParser({
    description: 'Traffic report analyzer (onboarding trial task). For functionality spec, ' +
        'see https://github.com/cyboman32/traf_exercise'
});

ap.add_argument('in-file', {type: 'str', nargs: '?', help: 'input report file to parse', default: default_infile})

const args = ap.parse_args();

const input_file = args['in-file'];
const results = [];

const unique_mac_addresses = new Set();
const unique_ip_addresses = new Set();
const unique_mac_ip_pairs = new Set();

let total_bytes = 0;
let total_time = 0.0;

let total_udp_bytes = 0;
let total_udp_time = 0.0;

let max_speed = 0.0;
let max_speed_transfer = [];

const transfers = new Map();
const mutual_transfers = new Map();

const traffic_by_node = new Map();
const time_by_node = new Map();

const sessions_by_network = new Map();

function mac_canonical(mac_address) {
    const octets = mac_address.split(':');
    if (octets.length !== 6) {
        throw new Error(`Cannot parse MAC: ${mac_address}: Octets number do not match.`);
    }
    return octets.map(octet => {
        if (octet === "") {
            throw new Error(`Cannot parse MAC: ${mac_address}: empty octet.`);
            //return '0';
        }
        return octet;
    }).map(octet => {
        const intValue = parseInt(octet, 16);
        if (isNaN(intValue) || intValue > 255 || intValue < 0) {
            throw new Error(`Cannot parse MAC: ${mac_address}: wrong hex value`);
        }
        return intValue;
    }).map(octetInt => octetInt.toString(16).toUpperCase().padStart(2, '0')).join(':');
}

function is_ip_24_subnet(ip_address) {
    const octets = ip_address.split('.').map((octet, index, array) => {
        const intValue = parseInt(octet);
        if (isNaN(intValue) || intValue > 255 || intValue < 0) {
            throw new Error(`Cannot parse IPv4: ${ip_address}: wrong hex value`);
        }
        return intValue.toString(2).padStart(8, '0');
    });

    if (octets.length != 4) {
        throw new Error(`Invalid IP address: ${ip_address}`);
    }

    return octets[0].startsWith('110');
}

function update_network_sessions_count(ip_address) {
    if (is_ip_24_subnet(ip_address)) {
        const octets = ip_address.split('.');
        const subnet_id = octets.slice(0, 3).join('.') + `.0`
        const current_network_sessions = set_default(sessions_by_network, subnet_id, 0);
        sessions_by_network.set(subnet_id, current_network_sessions + 1);
    }
}

function set_default(map, key, default_value) {
    if (!map.has(key)) {
        map.set(key, default_value);
    }
    return map.get(key);
}

function append_value(map, key, value) {

    const values = set_default(map, key, []);
    values.push(value);
}

function get_protocol(record) {

    if (record.is_udp !== 'true' && record.is_udp !== 'false') {
        throw new Error(`Wrong protocol flag: ${record.is_udp}`);
    }
    return record.is_udp === 'true' ? 'UDP' : 'TCP';
}

function validate_mutual_communication_records(src_records, dst_records, src_mac, dst_mac) {

    const errors = [];
    // check that the record lists are not empty
    if (src_records.length === 0) {
        errors.push('Source records are empty.')
    }
    if (dst_records.length === 0) {
        errors.push('Destination records are empty.')
    }
    // check that src records directed to dst_mac and vice versa; check that protocols are equal
    const is_udp = src_records[0].is_udp
    for (const src_record of src_records) {
        if (src_record.src_mac !== src_mac) {
            errors.push(`src record must originate from mac ${src_mac}, ${src_record.src_mac} found instead.`);
        }
        if (src_record.dst_mac !== dst_mac) {
            errors.push(`src record must direct to mac ${dst_mac}, ${src_record.dst_mac} found instead.`);
        }
        if (src_record.is_udp !== is_udp) {
            errors.push(`all records must have the udp flag set to ${is_udp}, ${src_record.is_udp} found instead.`);
        }
    }
    for (const dst_record of dst_records) {
        if (dst_record.src_mac !== dst_mac) {
            errors.push(`dst record must originate from mac ${dst_mac}, ${dst_record.src_mac} found instead.`);
        }
        if (dst_record.dst_mac !== src_mac) {
            errors.push(`dst record must direct to mac ${src_mac}, ${dst_record.dst_mac} found instead.`);
        }
        if (dst_record.is_udp !== is_udp) {
            errors.push(`all records must have the udp flag set to ${is_udp}, ${dst_record.is_udp} found instead.`);
        }
    }
    if (errors.length > 0) {
        console.error(`Errors registering communication ${src_mac} <-> ${dst_mac}:`);
        for (const error of errors) {
            console.error(error);
        }
        console.error('Aborting the registration.');
        return false;
    }
    return true;

}

function register_one_side_transfer(records, src_mac, dst_mac) {

    const protocol = get_protocol(records[0]);
    const mac_transfers = set_default(mutual_transfers, src_mac, new Map());
    const transfers_by_protocol = set_default(mac_transfers, protocol, new Map());
    const transfers_by_dst_mac = set_default(transfers_by_protocol, dst_mac, []);

    const registered_line_numbers = new Set(transfers_by_dst_mac.map(record => record.line));

    let changes = false;

    for (const record of records) {

        if (!registered_line_numbers.has(record.line)) {
            transfers_by_dst_mac.push(record);
            changes = true;
        } else {
            console.warn(`record ${record.line}:${protocol}:${record.src_mac} -> ${record.dst_mac}
              already registered in the suspect registry; `);
        }
    }
    return changes;
}

function register_mutual_transfer(src_mac, src_records, dst_mac, dst_records) {

    if (!validate_mutual_communication_records(src_records, dst_records, src_mac, dst_mac)) {
        console.warn('Mutual transfer registration failed due to validation errors.')
        return;
    }
    register_one_side_transfer(src_records, src_mac, dst_mac);
    register_one_side_transfer(dst_records, dst_mac, src_mac);
}

function register_transfer(transfers, record) {

    if (transfers.has(record.dst_mac)) {
        const by_dst = transfers.get(record.dst_mac);
        const protocol = get_protocol(record);
        if (by_dst.has(protocol)) {
            const by_dst_by_protocol = by_dst.get(protocol);
            if (by_dst_by_protocol.has(record.src_mac)) {
                const back_talks = by_dst_by_protocol.get(record.src_mac);
                if (back_talks.length > 0) {
                    // two-directional interaction detected
                    // register src -> dst and dst -> src communictions in the mutual_transfers map
                    console.log(`two-sided activity detected: ${record.src_mac} <-> ${record.dst_mac}`);
                    console.log(`protocol is ${get_protocol(record)}`);
                    console.log(`detected in log record: \n 
                        ${util.inspect(record, false, null, true)}`);
                    console.log(`known back talks: \n 
                        ${util.inspect(back_talks, false, null, true)}`);
                    register_mutual_transfer(record.src_mac, [record], record.dst_mac, back_talks);

                }
            }
        }
    }
    const mac_transfers = set_default(transfers, record.src_mac, new Map());

    const transfers_by_protocol = set_default(mac_transfers, get_protocol(record), new Map());
    const transfers_by_partner = set_default(transfers_by_protocol, record.dst_mac, []);
    transfers_by_partner.push(record);
}

var line_number = 0;

fs.createReadStream(input_file)
    .on('error', (err) => {
        console.error(`Error opening the input file ${input_file}: ${err}`);
    })
    .pipe(CsvParser({headers: headers, separator: field_delimiter}))
    .on('data', (data) => {
        //console.log(data);
        try {
            const [src_ip, src_port] = IpPortParser(data.src_ip_port);
            const [dst_ip, dst_port] = IpPortParser(data.dst_ip_port);

            data.src_mac = mac_canonical(data.src_mac);
            data.dst_mac = mac_canonical(data.dst_mac);

            const protocol = get_protocol(data);

            data = {line: line_number, ...data, src_ip: src_ip, src_port: src_port, dst_ip: dst_ip, dst_port: dst_port,
                protocol: protocol};

            unique_mac_addresses.add(data.src_mac);
            unique_mac_addresses.add(data.dst_mac);
            unique_ip_addresses.add(src_ip);
            unique_ip_addresses.add(dst_ip);
            unique_mac_ip_pairs.add(`${data.src_mac};${src_ip}`);
            unique_mac_ip_pairs.add(`${data.dst_mac};${dst_ip}`);

            try {
                const bytes_sent = parseInt(data.data_size);
                if (isNaN(bytes_sent) || bytes_sent <= 0) {
                    throw new Error(`bytes number must be a positive integer, got ${data.data_size} instead.`);
                }
                const transfer_time = parseFloat(data.time_interval);
                if (isNaN(transfer_time) || transfer_time <= 0) {
                    throw new Error(`transfer time must be a positive float, got ${data.time_interval} instead.`);
                }
                total_bytes += bytes_sent;
                total_time += transfer_time;

                data.data_size = bytes_sent;
                data.time_interval = transfer_time;

                const speed = bytes_sent / transfer_time;
                data = {...data, speed: speed };
                if (protocol === 'UDP') {
                    total_udp_bytes += bytes_sent;
                    total_udp_time += transfer_time;
                }
                if (max_speed < speed) {
                    max_speed = speed;
                    max_speed_transfer = data;
                }

                const node_traffic = set_default(traffic_by_node, data.src_mac, 0);
                traffic_by_node.set(data.src_mac, node_traffic + bytes_sent);

                const node_transfer_time = set_default(time_by_node, data.src_mac, 0.0);
                time_by_node.set(data.src_mac, node_transfer_time + transfer_time);
            } catch (e) {
                console.warn(e);
                data.speed = 'INVALID';
            }

            try {
                update_network_sessions_count(data.src_ip);
                update_network_sessions_count(data.dst_ip);
            } catch (e) {
                console.warn('Error updating network session count:', e);
            }

            results.push(data);
            register_transfer(transfers, data);
        } catch (e) {
            console.warn(`Error parsing transfer data at line ${line_number}: \n ${e}`);
        } finally {
            line_number++;
        }

    })
    .on('error', (err) => {
        console.warn(`Error parsing CSV line ${line_number}: \n ${err}`);
    })
    .on('end', () => {
        console.log('Q1:');
        console.log(`Data contains ${unique_mac_addresses.size} unique MAC addresses`);
        console.log(`Data contains ${unique_ip_addresses.size} unique IP addresses`);
        console.log(`Data contains ${unique_mac_addresses.size} unique MAC+IP address combinations`);
        console.log('-------------------------------');

        console.log('Q2:');
        const total_avg_speed = total_bytes / total_time;
        console.log(`${total_bytes} bytes were sent at ${total_time} seconds.`);
        console.log(`Total average speed is ${total_avg_speed} b/sec.`);
        console.log('-------------------------------');

        console.log('Q3:');
        const avg_udp_speed = total_udp_bytes / total_udp_time;
        console.log('UDP statistics:');
        console.log(`${total_udp_bytes} bytes sent at ${total_udp_time} sec.`);
        console.log(`Average UDP transfer speed is ${avg_udp_speed} b/sec.`)
        console.log(`Total peak speed is ${max_speed}.`);
        console.log('Peak speed was reached at transfer:');
        console.log(max_speed_transfer);
        console.log(`Is UDP transfer always at peak speed: ${avg_udp_speed >= max_speed ? 'YES' : 'NO'}.`);
        console.log('-------------------------------');

        console.log('Q4:');
        const node_speeds = new Map();
        traffic_by_node.forEach((bytes, node, map) => {
            const time = time_by_node.get(node);
            const node_speed = bytes / time;
            node_speeds.set(node, node_speed);
        });
        const sorted_node_speeds = new Map([...node_speeds.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, top_nodes_list_size));

        console.log(`Top ${top_nodes_list_size} speediest nodes: `)
        console.log(util.inspect(sorted_node_speeds, false, 3, true));
        console.log('-------------------------------');

        console.log('Q5:');
        console.log(`Top ${top_networks_list_size} class C networks by sessions count:`);
        const top_networks_by_session = new Map([...sessions_by_network.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, top_networks_list_size)
        );
        console.log(util.inspect(top_networks_by_session, false, 3, true));
        console.log('-------------------------------');

        console.log('Q6:');
        console.log('Detected mutual transfers:');
        const out_mutual_transfers_data = new Map([...mutual_transfers.entries()].sort());
        console.log(util.inspect(out_mutual_transfers_data, false, 3, true));
        console.log('Nodes with more than one mutual transfer (proxies by the task criteria:');

        const proxies = new Map([...out_mutual_transfers_data.entries()].filter(([key, value]) => {
            let partners_num = 0;
            value.forEach((protocol, nodes, map) => partners_num += nodes.size);
            return partners_num > 1;
        }));
        proxies.forEach((value, key, map) => {
            console.log(`${key} communicated with ${value.keys()}`);
        })
        console.log(util.inspect(proxies, false, 3, true));
    })


