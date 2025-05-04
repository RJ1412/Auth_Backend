import express from "express";
import { register , login , logout , sendVerifyOtp ,verifyOtp, forgetpassword, resetpassword } from "../controllers/controller_auth.js";
import {userAuth} from "../middleware/auth_middleware.js"
const authRoutes = express.Router();

authRoutes.post("/register" , register)

authRoutes.post("/login" , login)

authRoutes.post("/logout" ,userAuth, logout)

authRoutes.post("/send-verify-otp" ,  sendVerifyOtp)

authRoutes.post("/verify-account"  ,  verifyOtp)

authRoutes.post("/send-reset-otp", forgetpassword);
authRoutes.post("/reset-password", resetpassword);




export default authRoutes;