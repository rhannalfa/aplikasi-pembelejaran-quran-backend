const bcrypt = require('bcrypt');
const crypto = require("crypto");
const nodemailer = require("nodemailer");
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

        // Periksa status user
        if (user.user_status === "Inactive") {
            return res.status(403).json({
                message: "Your account is inactive. Please contact the admin or re-register.",
            });
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
            },
        });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Error logging in." });
    }
});

app.post("/logout", (req, res) => {
    // Respons logout berhasil
    res.status(200).json({ message: "Logout successful." });
});

app.get("/reset-password", async (req, res) => {
    const { token } = req.query;

    try {
        // Validasi input token
        if (!token) {
            return res.status(400).json({ Token: "Token is required." });
        }

        // Cari token di database
        const tokenData = await knex("password_resets").where({ token }).first();

        if (!tokenData) {
            return res.status(404).json({ message: "Invalid or expired token." });
        }

        // Periksa apakah token sudah kedaluwarsa
        const currentTime = new Date();
        if (currentTime > tokenData.expires_at) {
            return res.status(400).json({ message: "Token has expired." });
        }

        // Token valid, respons berhasil
        res.status(200).json({
            message: "Token is valid.",
            token: token,
        });
    } catch (error) {
        console.error("Error in reset-password validation:", error);
        res.status(500).json({ message: "An unexpected error occurred. Please try again later." });
    }
});

app.post("/reset-password", async (req, res) => {
    const { password } = req.body;
    const { token } = req.query;

    try {
        // Validasi input
        if (!password) {
            return res.status(400).json({ message: "Password is required." });
        }
        if (!token) {
            return res.status(400).json({ message: "Token is required." });
        }

        // Cari token di database
        const resetRequest = await knex("password_resets")
            .where({ token })
            .andWhere("expires_at", ">", new Date()) // Token tidak boleh kadaluarsa
            .first();

        if (!resetRequest) {
            return res.status(400).json({ message: "Invalid or expired token." });
        }

        // Hash password baru
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update password user
        await knex("users")
            .where({ email: resetRequest.email })
            .update({ password: hashedPassword });

        // Hapus token setelah digunakan
        await knex("password_resets").where({ token }).del();

        // Respons berhasil
        res.status(200).json({ message: "Password has been reset successfully." });
    } catch (error) {
        console.error("Error in reset-password:", error);
        res.status(500).json({ message: "An unexpected error occurred. Please try again later." });
    }
});

app.post("/forget-password", async (req, res) => {
    const { email } = req.body;

    try {
        // Validasi input
        if (!email) {
            return res.status(400).json({ message: "Email is required." });
        }

        // Cari user berdasarkan email
        const user = await knex("users").where({ email }).first();

        if (!user) {
            return res.status(404).json({ message: "User not found. Please check the email address." });
        }

        // Generate token unik
        const token = crypto.randomBytes(32).toString("hex");
        const expirationTime = new Date();
        expirationTime.setHours(expirationTime.getHours() + 1); // Token berlaku selama 1 jam

        // Simpan token dan waktu kedaluwarsa di database
        await knex("password_resets").insert({
            email: user.email,
            token: token,
            expires_at: expirationTime,
        });

        // Buat link reset password
        const resetLink = `http://localhost:4000/reset-password?token=${token}`;

        // Konfigurasi transporter email
        const transporter = nodemailer.createTransport({
            service: "Gmail", // Bisa diganti dengan layanan lain seperti SendGrid, Outlook, dll.
            auth: {
                user: "raihanalf9c@gmail.com", // Ganti dengan email Anda
                pass: "rejb tqkd whys jrka", // Ganti dengan password email Anda
            },
        });

        // Opsi email dengan HTML
        const mailOptions = {
            from: "raihanalf9c@gmail.com", // Ganti dengan email Anda
            to: email,
            subject: "Password Reset Request",
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; padding: 20px;">
                    <h2 style="text-align: center; color: #007BFF;">Password Reset Request</h2>
                    <p>Hello <b>${user.name}</b>,</p>
                    <p>You requested a password reset. Click the button below to reset your password:</p>
                    <table cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 20px auto;">
                        <tr>
                            <td align="center" bgcolor="#007BFF" style="border-radius: 4px;">
                                <a href="${resetLink}" 
                                   style="display: inline-block; font-size: 16px; color: #ffffff; text-decoration: none; padding: 10px 20px; background-color: #007BFF; border-radius: 4px;">
                                   Reset Password
                                </a>
                            </td>
                        </tr>
                    </table>
                    <p>If the button above does not work, copy and paste the following link into your browser:</p>
                    <p style="word-wrap: break-word;">
                        <a href="${resetLink}" style="color: #007BFF;">${resetLink}</a>
                    </p>
                    <p>If you did not request this, please ignore this email. This link will expire in 1 hour.</p>
                    <hr style="border: 0; border-top: 1px solid #ddd;">
                    <p style="text-align: center; font-size: 12px; color: #777;">
                        © 2025 Your Company Name. All rights reserved.<br>
                        Need help? <a href="mailto:support@example.com" style="color: #007BFF;">Contact Support</a>.
                    </p>
                </div>
            `,
        };          

        // Kirim email
        await transporter.sendMail(mailOptions);

        // Respons berhasil
        res.status(200).json({ message: "Password reset link has been sent to your email." });
    } catch (error) {
        console.error("Error in forget-password:", error);
        res.status(500).json({ message: "An unexpected error occurred. Please try again later." });
    }
});





