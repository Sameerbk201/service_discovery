const dgram = require('dgram');

const mdnsAddress = '224.0.0.251';
const mdnsPort = 5353;

// According to the documentation, the query is sent as '_smart_ip._tcp'
const serviceQuery = '_smart_ip._tcp';
// For forming the fully qualified domain name (FQDN) for mDNS queries, we append '.local'
const fullServiceQuery = serviceQuery + '.local';

const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

// Build a DNS query packet for a PTR record for the service.
// We use the FQDN version for the query.
function buildQuery() {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0, 0);      // ID = 0 (mDNS uses 0)
    header.writeUInt16BE(0, 2);      // Flags = 0
    header.writeUInt16BE(1, 4);      // QDCOUNT = 1
    header.writeUInt16BE(0, 6);      // ANCOUNT = 0
    header.writeUInt16BE(0, 8);      // NSCOUNT = 0
    header.writeUInt16BE(0, 10);     // ARCOUNT = 0

    // Build the QNAME for the full service query (e.g. "_smart_ip._tcp.local")
    const qnameParts = fullServiceQuery.split('.');
    let qnameBufferArray = [];
    for (const part of qnameParts) {
        if (!part) continue;
        const len = Buffer.alloc(1);
        len.writeUInt8(part.length, 0);
        qnameBufferArray.push(len);
        qnameBufferArray.push(Buffer.from(part));
    }
    // Terminate with a zero byte
    qnameBufferArray.push(Buffer.from([0]));
    const qnameBuffer = Buffer.concat(qnameBufferArray);

    // Question section: QTYPE (PTR = 12) and QCLASS (IN = 1)
    const question = Buffer.alloc(4);
    question.writeUInt16BE(12, 0);
    question.writeUInt16BE(1, 2);

    return Buffer.concat([header, qnameBuffer, question]);
}

// Helper to read a domain name from the buffer (supports compression pointers)
function readName(buffer, offset) {
    let labels = [];
    let jumped = false;
    let originalOffset = offset;

    while (true) {
        const length = buffer.readUInt8(offset);
        if (length === 0) {
            offset += 1;
            break;
        }
        // Check for pointer (two highest bits set)
        if ((length & 0xC0) === 0xC0) {
            const pointer = ((length & 0x3F) << 8) | buffer.readUInt8(offset + 1);
            if (!jumped) {
                originalOffset = offset + 2;
            }
            offset = pointer;
            jumped = true;
            continue;
        }
        offset += 1;
        const label = buffer.toString('utf8', offset, offset + length);
        labels.push(label);
        offset += length;
    }
    return { name: labels.join('.'), readBytes: jumped ? originalOffset : offset };
}

// Parse one DNS record from the buffer starting at the given offset
function parseRecord(buffer, offset) {
    const nameResult = readName(buffer, offset);
    const name = nameResult.name;
    offset = nameResult.readBytes;

    const type = buffer.readUInt16BE(offset);
    offset += 2;
    const cls = buffer.readUInt16BE(offset);
    offset += 2;
    const ttl = buffer.readUInt32BE(offset);
    offset += 4;
    const rdlength = buffer.readUInt16BE(offset);
    offset += 2;

    let rdata;
    if (type === 12) { // PTR
        rdata = readName(buffer, offset).name;
    } else if (type === 33) { // SRV
        const priority = buffer.readUInt16BE(offset);
        const weight = buffer.readUInt16BE(offset + 2);
        const port = buffer.readUInt16BE(offset + 4);
        const target = readName(buffer, offset + 6).name;
        rdata = { priority, weight, port, target };
    } else if (type === 16) { // TXT
        let txts = {};
        const end = offset + rdlength;
        while (offset < end) {
            const txtLen = buffer.readUInt8(offset);
            offset += 1;
            const txt = buffer.toString('utf8', offset, offset + txtLen);
            offset += txtLen;
            const equalIndex = txt.indexOf('=');
            if (equalIndex !== -1) {
                const key = txt.substring(0, equalIndex);
                const value = txt.substring(equalIndex + 1);
                txts[key] = value;
            } else {
                txts[txt] = true;
            }
        }
        rdata = txts;
        return { name, type, cls, ttl, rdlength, rdata, offset };
    } else if (type === 1) { // A record
        const ipBytes = [];
        for (let i = 0; i < rdlength; i++) {
            ipBytes.push(buffer.readUInt8(offset + i));
        }
        rdata = ipBytes.join('.');
    } else {
        rdata = buffer.slice(offset, offset + rdlength);
    }
    offset += rdlength;
    return { name, type, cls, ttl, rdlength, rdata, offset };
}

// Parse the full DNS message (header, questions, records)
function parseDNSMessage(buffer) {
    const header = {
        id: buffer.readUInt16BE(0),
        flags: buffer.readUInt16BE(2),
        qdcount: buffer.readUInt16BE(4),
        ancount: buffer.readUInt16BE(6),
        nscount: buffer.readUInt16BE(8),
        arcount: buffer.readUInt16BE(10),
    };
    let offset = 12;

    // Skip the questions
    for (let i = 0; i < header.qdcount; i++) {
        const res = readName(buffer, offset);
        offset = res.readBytes + 4; // skip QTYPE and QCLASS
    }

    const records = [];
    const totalRecords = header.ancount + header.nscount + header.arcount;
    for (let i = 0; i < totalRecords; i++) {
        const record = parseRecord(buffer, offset);
        records.push(record);
        offset = record.offset;
    }
    return { header, records };
}

// Helper: Check if a record name is associated with our smart_ip service.
// We expect service instance names to end with "._smart_ip._tcp.local"
function isSmartIPService(name) {
    return name === fullServiceQuery || name.endsWith('.' + fullServiceQuery);
}

// Store service details by instance name.
const services = {};

// Listen for incoming mDNS responses
socket.on('message', (msg, rinfo) => {
    console.log(`\nReceived mDNS response from ${rinfo.address}:${rinfo.port}`);
    try {
        const parsed = parseDNSMessage(msg);

        // Process each record and register only those related to our service.
        for (const rec of parsed.records) {
            // PTR record: links the query (fullServiceQuery) to a service instance name.
            if (rec.type === 12 && rec.name === fullServiceQuery) {
                const serviceInstance = rec.rdata;
                if (!services[serviceInstance]) {
                    services[serviceInstance] = { name: serviceInstance };
                }
            }
            // SRV record: provides the target and port (filter based on service instance name)
            else if (rec.type === 33 && isSmartIPService(rec.name)) {
                if (!services[rec.name]) {
                    services[rec.name] = { name: rec.name };
                }
                services[rec.name].port = rec.rdata.port;
                services[rec.name].target = rec.rdata.target;
            }
            // TXT record: holds additional properties (filter on service instance name)
            else if (rec.type === 16 && isSmartIPService(rec.name)) {
                if (!services[rec.name]) {
                    services[rec.name] = { name: rec.name };
                }
                services[rec.name].txt = rec.rdata;
            }
            // A record: maps a target name to an IP address.
            else if (rec.type === 1) {
                for (const instance in services) {
                    if (services[instance].target === rec.name) {
                        if (!services[instance].addresses) {
                            services[instance].addresses = [];
                        }
                        services[instance].addresses.push(rec.rdata);
                    }
                }
            }
        }

        // Output the discovered smart_ip services.
        for (const instance in services) {
            // Only output records whose names end with our expected suffix.
            if (!isSmartIPService(services[instance].name)) continue;
            // Strip the service type from the instance name for display.
            let displayName = services[instance].name;
            const suffix = '.' + fullServiceQuery;
            if (displayName.endsWith(suffix)) {
                displayName = displayName.substring(0, displayName.length - suffix.length);
            }
            console.log('----------------------------------------');
            console.log(`Service found:`);
            console.log(`Name: ${displayName}`);
            console.log(`IP Address(es): ${services[instance].addresses || []}`);
            console.log(`Port: ${services[instance].port}`);
            console.log(`Properties: ${JSON.stringify(services[instance].txt || {})}`);
        }
    } catch (e) {
        console.error('Error parsing mDNS response:', e);
    }
});

socket.on('error', (err) => {
    console.error(`Socket error:\n${err.stack}`);
    socket.close();
});

// Bind the socket and send our mDNS query.
// socket.bind(mdnsPort, () => {
//     socket.addMembership(mdnsAddress);
//     console.log(`Listening for mDNS responses on ${mdnsAddress}:${mdnsPort}`);
//     const query = buildQuery();
//     socket.send(query, 0, query.length, mdnsPort, mdnsAddress, () => {
//         console.log(`Sent mDNS query for ${serviceQuery}`);
//     });
// });


socket.bind(mdnsPort, '169.254.137.22', () => {
    // Join the multicast group using the specified local interface.
    socket.addMembership(mdnsAddress, '169.254.137.22');
    console.log(`Listening for mDNS responses on ${mdnsAddress}:${mdnsPort} via interface 169.254.137.22`);
    const query = buildQuery();
    socket.send(query, 0, query.length, mdnsPort, mdnsAddress, () => {
        console.log(`Sent mDNS query for ${serviceQuery}`);
    });
});