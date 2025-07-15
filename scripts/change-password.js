#!/usr/bin/env node

const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const readline = require('readline');
const path = require('path');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const db = new sqlite3.Database(path.join(__dirname, '..', 'data', 'feuerwehr.db'));

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

async function changePassword() {
  console.log('=== Passwort ändern ===\n');
  
  const username = await question('Benutzername: ');
  const newPassword = await question('Neues Passwort: ');
  
  // Validate password
  if (newPassword.length < 8) {
    console.error('\n❌ Passwort muss mindestens 8 Zeichen lang sein!');
    process.exit(1);
  }
  
  if (!/[A-Z]/.test(newPassword)) {
    console.error('\n❌ Passwort muss mindestens einen Großbuchstaben enthalten!');
    process.exit(1);
  }
  
  if (!/[a-z]/.test(newPassword)) {
    console.error('\n❌ Passwort muss mindestens einen Kleinbuchstaben enthalten!');
    process.exit(1);
  }
  
  if (!/\d/.test(newPassword)) {
    console.error('\n❌ Passwort muss mindestens eine Zahl enthalten!');
    process.exit(1);
  }
  
  if (!/[@$!%*?&]/.test(newPassword)) {
    console.error('\n❌ Passwort muss mindestens ein Sonderzeichen (@$!%*?&) enthalten!');
    process.exit(1);
  }
  
  // Hash password
  const hashedPassword = bcrypt.hashSync(newPassword, 12);
  
  // Update in database
  db.run(
    'UPDATE users SET password = ?, password_changed_at = CURRENT_TIMESTAMP WHERE username = ?',
    [hashedPassword, username],
    function(err) {
      if (err) {
        console.error('\n❌ Fehler beim Aktualisieren:', err.message);
        process.exit(1);
      }
      
      if (this.changes === 0) {
        console.error('\n❌ Benutzer nicht gefunden!');
        process.exit(1);
      }
      
      console.log('\n✅ Passwort erfolgreich geändert!');
      process.exit(0);
    }
  );
}

changePassword().catch(err => {
  console.error('Fehler:', err);
  process.exit(1);
});