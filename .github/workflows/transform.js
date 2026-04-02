const fs = require('fs');

// Read raw Airtable response
const raw = JSON.parse(fs.readFileSync('airtable_raw.json', 'utf8'));

// Transform Airtable records to our format
const reservations = (raw.records || []).map(record => {
    const fields = record.fields || {};
    
    return {
        id: record.id,
        team: String(fields['Booked By'] || '').slice(0, 64),
        date: fields['Date'] || '',
        slot: fields['Time Slot'] || '',
        inventory: Array.isArray(fields['Inventory']) 
            ? fields['Inventory'].slice(0, 10) 
            : [],
        createdAt: record.createdTime || new Date().toISOString()
    };
}).filter(r => r.team && r.date && r.slot);

// Write to data.json
fs.writeFileSync(
    'data.json',
    JSON.stringify({ reservations, syncedAt: new Date().toISOString() }, null, 2)
);

console.log(`Synced ${reservations.length} reservations.`);
