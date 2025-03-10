const bonjour = require('bonjour')();

const browser = bonjour.find({ type: 'smart_ip' });

browser.on('up', (service) => {
    console.log('Service found:');
    console.log('Name:', service.name);
    console.log('IP Address(es):', service.addresses);
    console.log('Port:', service.port);
    console.log('Properties:', service.txt);
    console.log('-'.repeat(40));
});

console.log('Searching for _smart_ip._tcp.local. services. Press Ctrl+C to exit.');
