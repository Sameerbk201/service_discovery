const mdns = require('multicast-dns')();

const SERVICE_NAME = '_smart_ip._tcp.local';

mdns.on('response', (response) => {
    response.answers.forEach((answer) => {
        if (answer.type === 'PTR' && answer.name === SERVICE_NAME) {
            console.log('Service Discovered:', answer.data);

            // Send another query to get detailed information (SRV, TXT, A/AAAA records)
            mdns.query(answer.data, 'SRV');
            mdns.query(answer.data, 'TXT');
            mdns.query(answer.data, 'A');
        }

        if (answer.type === 'SRV') {
            console.log(`SRV Record:`, answer);
        }

        if (answer.type === 'TXT') {
            console.log(`TXT Record:`, answer.data.toString());
        }

        if (answer.type === 'A') {
            console.log(`IP Address:`, answer.data);
        }
    });
});

// Initial PTR query for service discovery
mdns.query({
    questions: [{
        name: SERVICE_NAME,
        type: 'PTR'
    }]
});

console.log(`Searching for ${SERVICE_NAME} services... Press Ctrl+C to exit.`);
