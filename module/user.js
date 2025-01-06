const bcrypt = require('bcrypt');
const saltRounds = 10; 

app.get('/users', async (req, res) => {
    const results = await knex('users').select();
    res.json(results);
});


app.post("/register", async (req, res) => {
    const data = req.body;

    try {
        // Validasi data masuk
        if (!data.name || !data.email || !data.password || !data.id_role) {
            return res.status(400).json({ message: "Required fields are missing." });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(data.password, saltRounds);

        // Insert ke database
        const results = await knex("users").insert({
            name: data.name,
            email: data.email,
            password: hashedPassword,
            phone: data.phone,
            date_of_birth: data.date_of_birth,
            gender: data.gender,
            user_status: data.user_status || "Active",
            address: data.address,
            id_role: data.id_role || 3,
        });

        res.status(201).json({ message: "User registered successfully", userId: results[0] });
    } catch (error) {
        console.error("Error registering user:", error);

        if (error.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Email already exists." });
        }

        res.status(500).json({ message: "Error registering user" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validasi input
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }

        // Cari user berdasarkan email
        const user = await knex("users").where({ email }).first();

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // Verifikasi password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        // Tentukan pesan berdasarkan role
        let roleMessage = "";
        switch (user.id_role) {
            case 1:
                roleMessage = "Welcome back, Admin!";
                break;
            case 2:
                roleMessage = "Welcome, Instructor! Ready to teach?";
                break;
            case 3:
                roleMessage = "Hello, Student! Ready to learn?";
                break;
            default:
                roleMessage = "Welcome to the platform!";
        }

        // Respons login berhasil
        res.status(200).json({
            message: "Login successful",
            roleMessage,
            user: {
                id_user: user.id_user,
                name: user.name,
                email: user.email,
                role: user.id_role,
                status: user.user_status,
            },
        });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Error logging in." });
    }
});


