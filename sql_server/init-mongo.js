// Use the employee_db database
db = db.getSiblingDB('employee_db');

// Create a basic user for the program to access the users collection
db.createUser({
  user: "program_user",
  pwd: "program_password",
  roles: [
    { role: "readWrite", db: "employee_db" }
  ]
});

// Create the users collection if it doesn't exist
db.createCollection('users');

// Insert the 'admin' user with the encrypted password and role
db.users.insert({
  username: "admin",
  password_hash: "1a520e011a5a2d03150a153816",  // The encrypted admin password
  role: "admin"  // Assign the role of "admin"
});

// Insert the 'super' user with the encrypted password and super admin role
db.users.insert({
  username: "super_admin",
  password_hash: "1a341d471a360140170c145c2d1d0001071e0a",  // The encrypted super admin password
  role: "super_admin"  // Assign the role of "super_admin"
});

// Create the admin collection if it doesn't exist
db.createCollection('admin');

// Insert an admin user with a password "h4ck3d!" (hashed password for security)
db.admin.insert({
  username: "admin_user",
  password_hash: "3c0b614ecf5dfc13c03e5b745d3820b1",  // Simulated hash of "h4ck3d!"
  sensitive_data: "h4ck3d!",  // Placeholder for sensitive info
  role: "admin"
});