import { db } from "../libs/db.js";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import transporter from "../libs/nodemailer.js";
import { generateEmailTemplate } from "../libs/emailTemplates.js";
dotenv.config();



let tempUsers = new Map(); // temporary in-memory storage (use Redis or DB for production)

export const register = async (req, res) => {
    const { username, email, password, name } = req.body;

    if (!username || !email || !password || !name) {
        return res.status(400).json({ error: "All fields required" });
    }

    try {
        const existingUser = await db.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        const hashedPassword = await bcrypt.hash(password, 10);

        tempUsers.set(email, {
            username,
            email,
            password: hashedPassword,
            name,
            otp,
            expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
        });

        const otpEmail = generateEmailTemplate("otp", {
            name,
            otp,
            expires: "24 hours",
        });

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: otpEmail.subject,
            html: otpEmail.html,
        });

        res.status(200).json({
            message: "OTP sent to your email. Verify to complete registration.",
        });
    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ error: "Failed to initiate registration" });
    }
};

export const verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;

        const tempUser = tempUsers.get(email);
        if (!tempUser) {
            return res.status(400).json({ error: "No registration found. Please register again." });
        }

        if (Date.now() > tempUser.expiresAt) {
            tempUsers.delete(email);
            return res.status(400).json({ error: "OTP expired. Please register again." });
        }

        if (tempUser.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }

        const newUser = await db.user.create({
            data: {
                username: tempUser.username,
                email: tempUser.email,
                password: tempUser.password,
                name: tempUser.name,
                IsVerified: true,
            },
        });

        tempUsers.delete(email); 

        const welcomeEmail = generateEmailTemplate("welcome", {
            name: newUser.name,
            email: newUser.email,
        });

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: newUser.email,
            subject: welcomeEmail.subject,
            html: welcomeEmail.html,
        });

        res.status(201).json({ message: "User verified and registered successfully." });
    } catch (error) {
        console.error("Verify OTP Error:", error);
        res.status(500).json({ error: "Verification failed" });
    }
};


export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: "All Fields Required"
        });
    }

    try {
        const user = await db.user.findUnique({
            where: {
                email
            }
        });

        if (!user) {
            return res.status(400).json({
                error: "User not found"
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                error: "Invalid Credentials"
            });
        }

        if (!user.IsVerified) {
            const otp = String(Math.floor(100000 + Math.random() * 900000));

            await db.user.update({
                where: { email },
                data: {
                    VerificationToken: otp,
                    VerifyOtpExpireAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
                },
            });

            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: email,
                subject: "Verify Your Account",
                text: `Your OTP is ${otp}`,
            };
            await transporter.sendMail(mailOptions);

            return res.status(403).json({
                message: "Account not verified. OTP resent.",
                redirectToOtp: true,
            });
        }

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.cookie("token", token, {
            httpOnly: true,
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 24 * 7
        });

        res.status(200).json({
            success: true,
            message: "User Logged In Successfully",
            user: {
                id: user.username,
                email: user.email,
                name: user.name,
            }
        });
    } catch (error) {
        console.log("Error logging in:", error);
        res.status(500).json({
            error: "Invalid Credential"
        });
    }
};


export const sendVerifyOtp = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await db.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(400).json({ error: "User Not Found" });
        }

        if (user.IsVerified) {
            return res.status(400).json({ message: "User Already Verified" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        await db.user.update({
            where: { email },
            data: {
                VerificationToken: otp,
                VerifyOtpExpireAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h expiry
            },
        });

        const otpEmail = generateEmailTemplate("otp", {
            name: user.name,
            otp,
            expires: "24 hours",
          });
          
          await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: otpEmail.subject,
            html: otpEmail.html,
          });


        res.json({ message: "Verification mail sent" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Can't send OTP" });
    }
};



export const logout = async (req, res) => {
    try {
        res.clearCookie("jwt", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV !== "development"
        });
        res.clearCookie("token", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV !== "development"
        });

        res.status(200).json({
            success: true,
            message: "User logged out successfully"
        });
    } catch (error) {
        console.log("Error logging out user:", error);
        res.status(500).json({
            error: "Error logging out user"
        });
    }
};

export const forgetpassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: "All fields required"
            });
        }

        const user = await db.user.findUnique({ where: { email } });
        if (!user) return res.status(404).json({ error: "User not found" });

        const resetToken = String(Math.floor(100000 + Math.random() * 900000));
        const expiry = new Date(Date.now() + 1000 * 60 * 10); // 10 minutes

        await db.user.update({
            where: { email },
            data: { resetToken, resetTokenExpiry: expiry },
        });

        const resetEmail = generateEmailTemplate("reset-password", {
            otp: resetToken,
            expires: "10 minutes",
          });
          await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: resetEmail.subject,
            html: resetEmail.html,
          });


        console.log(`Reset link: http://localhost:3000/reset-password/${resetToken}`);
        res.json({ message: "Reset link sent to email" });
    } catch (error) {
        console.log(error);
        return res.status(400).json({
            error: "Can't send the link"
        });
    }
};


export const resetpassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const user = await db.user.findUnique({
        where: {
            email
        },
    });

    if (!user) return res.status(400).json({ error: "Invalid or expired token" });

    try {
        if (otp !== user.resetToken) {
            return res.status(400).json({
                error: "Invalid OTP"
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.user.update({
            where: { email },
            data: {
                password: hashedPassword,
                resetToken: "",
                resetTokenExpiry: null,
            },
        });

        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        console.log(error);
        return res.status(400).json({
            error: "Failed to reset password"
        });
    }
};
