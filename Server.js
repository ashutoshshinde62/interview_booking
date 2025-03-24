const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const hashedPassword = bcrypt.hashSync('adminpassword', 10);
console.log(hashedPassword);
const app = express();
const PORT = 3000;
const session = require('express-session');
const JWT_SECRET = process.env.JWT_SECRET;
const cors = require('cors');

// Middleware
// Update the delete endpoint to include authentication
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://your-app-name.onrender.com' : 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// Middleware to check JWT token
// Update isAuthenticated middleware
const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.redirect('/login.html');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded.user) {
      res.clearCookie('token');
      return res.redirect('/login.html');
    }
    req.user = decoded.user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.redirect('/admin-login.html');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded.admin) {
      res.clearCookie('token');
      return res.redirect('/admin-login.html');
    }
    req.admin = decoded.admin;
    next();
  });
};

const fetchAdditionalData = async (req, res, next) => {
  try {
    const { phone } = req.body; // Extract mobileNumber from the request body

    if (!phone) {
      return res.status(400).json({ error: 'Mobile number is required' });
    }

    // Fetch data from the database
    const [additionalData] = await db.promise().query(
      'SELECT * FROM users_admin WHERE mobile_number = ?',
      [phone]
    );

    // Attach the data to the request object
    req.additionalData = additionalData;
    console.log('Middleware Data:', additionalData); // Log the middleware data
    next(); // Move to the next middleware or route handler
  } catch (error) {
    console.error('Middleware Error:', error); // Log the middleware error
    res.status(500).json({ error: 'Failed to fetch additional data' });
  }
};


app.post('/register' ,fetchAdditionalData, async (req, res) => {
  console.log('Request Body:', req.body);
  const { username, email, phone, password } = req.body;
  const additionalData = req.additionalData;
  console.log('Additional Data:', additionalData);
  try {
      // Check if the user already exists
      const [existingUser] = await db.promise().query(
        'SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?',
        [username, email, phone]
      );

    if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Username or email or Mobile Number already exists' });
      }

    const [ashu] = await db.promise().query(
        'SELECT * FROM users WHERE phone = ?',
        [phone]
      );

    console.log(ashu);

    if (additionalData.length === 0) {
        return res.status(400).json({ message: 'Mobile number not authorized for registration' });
      }

      // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

      // Insert the new user into the database
    await db.promise().query(
        'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
        [username, email, phone, hashedPassword]
      );

    res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  });

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Fetch the user from the database
    const [user] = await db.promise().query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (user.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Compare the password
    const isMatch = await bcrypt.compare(password, user[0].password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token with user ID
    const token = jwt.sign({ user: { id: user[0].id } }, JWT_SECRET, { expiresIn: '1h' });

    // Set token in HTTP-only cookie
    res.cookie('token', token, { 
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      sameSite: 'lax',
    });

    res.json({ redirect: '/dashboard.html' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin Login
app.post('/admin-login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Fetch the admin from the database
    const [admin] = await db.promise().query(
      'SELECT * FROM admins WHERE username = ?',
      [username]
    );

    // Check if the admin exists
    if (admin.length === 0) {
      return res.status(400).json({ message: 'Admin not found' });
    }

    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, admin[0].password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token with admin ID
    const token = jwt.sign(
      { admin: { id: admin[0].id, role: 'admin' } }, // Add role
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    // Set token in HTTP-only cookie
    res.cookie('token', token, { 
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      sameSite: 'lax',
    });

    res.json({ redirect: '/admin-dashboard.html' });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/register-user', isAdmin, async (req, res) => {
  const { fullName, phone, email, role } = req.body;

  try {
    // Insert the new user into the database
    await db.promise().query(
      'INSERT INTO users_admin (full_name, mobile_number, email, role) VALUES (?, ?, ?, ?)',
      [fullName, phone, email, role]
    );

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/user',isAuthenticated, async (req, res) => {
  try {
    // Fetch the token from cookies
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    // Verify the token and decode the payload
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded token:', decoded); // Debugging

    // Extract the user ID from the decoded payload
    const userId = decoded.user.id;
    if (!userId) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    // Fetch the user from the database
    const [user] = await db.promise().query(
      'SELECT * FROM users WHERE id = ?',
      [userId]
    );

    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ username: user[0].username });
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/book-slot',isAuthenticated, async (req, res) => {
  const { studentName, date, time } = req.body;

  try {
    // Fetch the user ID from the token
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.user.id;

    // Check if the slot is already booked
    const [existingSlot] = await db.promise().query(
      'SELECT * FROM slots WHERE date = ? AND time = ?',
      [date, time]
    );

    if (existingSlot.length > 0) {
      return res.status(400).json({ message: 'Slot already booked' });
    }

    // Insert the new slot into the database
    await db.promise().query(
      'INSERT INTO slots (student_name, date, time, user_id) VALUES (?, ?, ?, ?)',
      [studentName, date, time, userId]
    );

    res.json({ message: 'Slot booked successfully' });
  } catch (err) {
    console.error('Error booking slot:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/check-availability', isAuthenticated, async (req, res) => {
  const { date } = req.body;

  try {
    // Fetch all booked slots for the given date
    const [bookedSlots] = await db.promise().query(
      'SELECT student_name, time FROM slots WHERE date = ?',
      [date]
    );

    // Format the booked slots as "student_name - time"
    const bookedSlotsList = bookedSlots.map(slot => `${slot.student_name} - ${slot.time}`);

    res.json({ bookedSlots: bookedSlotsList });
  } catch (err) {
    console.error('Error checking availability:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to fetch booked slots
app.get('/get-booked-slots', isAuthenticated, (req, res) => {
  const query = `
    SELECT 
      id, 
      student_name, 
      DATE_FORMAT(date, '%d-%m-%Y') AS formatted_date, 
      time 
    FROM slots
  `;; 
  db.query(query, (err, results) => { // Changed 'connection' to 'db'
    if (err) {
      console.error('Error executing MySQL query:', err); 
      return res.status(500).json({ message: 'Error fetching slots' });
    }
    res.json(results);
  });
});

// Delete slot endpoint
app.delete('/delete-slot/:id', async (req, res) => {
  const slotId = req.params.id;
  
  try {
    const [result] = await db.promise().query(
      'DELETE FROM slots WHERE id = ?',
      [slotId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Slot not found' });
    }

    res.json({ message: 'Slot deleted successfully' });
  } catch (err) {
    console.error('Delete slot error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/get-users', isAdmin, (req, res) => {
  const query = 'SELECT id, username, email, phone FROM users';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ message: 'Error fetching users' });
    }
    res.json(results);
  });
});

// Delete user endpoint
app.delete('/delete-user/:id', (req, res) => {
  const userId = req.params.id;
  
  db.query(
    'DELETE FROM users WHERE id = ?',
    [userId],
    (err, result) => {
      if (err) {
        console.error('Delete user error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({ message: 'User deleted successfully' });
    }
  );
});

// Get admin-registered users
app.get('/get-admin-users', isAdmin, (req, res) => {
  const query = 'SELECT id, full_name, mobile_number, email, role FROM users_admin';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching admin users:', err);
      return res.status(500).json({ message: 'Error fetching users' });
    }
    res.json(results);
  });
});

// Delete admin user endpoint
app.delete('/delete-admin-user/:id', isAdmin, (req, res) => {
  const userId = req.params.id;
  
  db.query(
    'DELETE FROM users_admin WHERE id = ?',
    [userId],
    (err, result) => {
      if (err) {
        console.error('Delete admin user error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({ message: 'User deleted successfully' });
    }
  );
});

// Regular user dashboard
app.get('/dashboard.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Admin dashboard
app.get('/admin-dashboard.html', isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});


// Protect all dashboard routes
app.get(['/dashboard*', '/admin-dashboard*'], (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.redirect('/');
  }
  
  // Verify token for regular users
  if (req.path.startsWith('/dashboard')) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err || !decoded.user) {
        res.clearCookie('token');
        return res.redirect('/');
      }
      next();
    });
  }
  
  // Verify token for admin dashboard
  if (req.path.startsWith('/admin-dashboard')) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err || !decoded.admin) {
        res.clearCookie('token');
        return res.redirect('/admin-login.html');
      }
      next();
    });
  }
});


// Serve protected pages
app.get('/dashboard(.html)?', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin-dashboard(.html)?', isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/auth-check', (req, res) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ 
      redirectUrl: req.path.includes('admin') ? 
        '/admin-login.html' : 
        '/'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      res.clearCookie('token');
      return res.status(401).json({ 
        redirectUrl: decoded?.admin ? 
          '/admin-login.html' : 
          '/' 
      });
    }
    res.status(200).json({ valid: true });
  });
});

// Logout route
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('http://localhost:3000');
});



// Protected dashboard route
app.get('/dashboard.html', isAuthenticated, (req, res) => {
  res.redirect('/');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
