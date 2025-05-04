// libs/emailTemplates.js

export const generateEmailTemplate = (type, data = {}) => {
    switch (type) {
      case "welcome":
        return {
          subject: "Welcome to DevDashboard!",
          html: `
            <div style="font-family:Arial, sans-serif; max-width:600px; margin:auto; background:#111; padding:20px; color:#fff; border-radius:8px;">
              <h2 style="text-align:center;">Welcome, ${data.name}!</h2>
              <p>Thanks for signing up with <strong>DevDashboard</strong>.</p>
              <p>Your registered email: <strong>${data.email}</strong></p>
              <p>Please verify your account to get started.</p>
              <hr style="border-color:#333;">
              <p style="font-size:12px; color:#888;">If you didn’t create this account, please ignore this email.</p>
            </div>
          `,
        };
  
      case "otp":
        return {
          subject: "Your Verification OTP - DevDashboard",
          html: `
            <div style="font-family:Arial, sans-serif; max-width:600px; margin:auto; background:#111; padding:20px; color:#fff; border-radius:8px;">
              <h2 style="text-align:center;">Account Verification</h2>
              <p>Hello ${data.name || "User"},</p>
              <p>Your One-Time Password (OTP) is:</p>
              <h1 style="text-align:center; background:#222; padding:10px; border-radius:6px; color:#0f0;">${data.otp}</h1>
              <p>This code will expire in <strong>${data.expires || "24 hours"}</strong>.</p>
              <hr style="border-color:#333;">
              <p style="font-size:12px; color:#888;">If you didn’t request this, you can safely ignore this email.</p>
            </div>
          `,
        };
  
      case "reset-password":
        return {
          subject: "Reset Your Password - DevDashboard",
          html: `
            <div style="font-family:Arial, sans-serif; max-width:600px; margin:auto; background:#111; padding:20px; color:#fff; border-radius:8px;">
              <h2 style="text-align:center;">Reset Password Request</h2>
              <p>We received a request to reset your password.</p>
              <p>Your OTP for password reset is:</p>
              <h1 style="text-align:center; background:#222; padding:10px; border-radius:6px; color:#ff0;">${data.otp}</h1>
              <p>This code will expire in <strong>${data.expires || "10 minutes"}</strong>.</p>
              <p>If you did not request this, please ignore this email.</p>
            </div>
          `,
        };
  
      default:
        return {
          subject: "Notification from DevDashboard",
          html: `<p>No template defined for this type.</p>`,
        };
    }
  };
  