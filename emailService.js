import nodemailer from 'nodemailer';

let transporter;

export const initEmailService = () => {
  if (!transporter) {
    const {
      SMTP_HOST,
      SMTP_PORT,
      SMTP_USER,
      SMTP_PASS,
      SMTP_FROM,
    } = process.env;

    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: parseInt(SMTP_PORT),
      secure: parseInt(SMTP_PORT) === 465,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    });
  }
  return transporter;
};

export const sendWelcomeEmail = async (email, name) => {
  const transporter = initEmailService();
  await transporter.sendMail({
    from: process.env.SMTP_FROM || '"MyPaidPost" <hello@mypaidpost.co.ke>',
    to: email,
    subject: 'Welcome to MyPaidPost!',
    text: `Hello ${name},\n\nWelcome to MyPaidPost! We're excited to have you on board.\n\nBest regards,\nThe MyPaidPost Team`,
    html: `<p>Hello ${name},</p><p>Welcome to MyPaidPost! We're excited to have you on board.</p><p>Best regards<br/>The MyPaidPost Team</p>`,
  });
};

export const sendPasswordResetEmail = async (email, resetToken) => {
  const transporter = initEmailService();
  const resetUrl = `${process.env.API_BASE_URL}/api/auth/reset-password?token=${resetToken}`;
  await transporter.sendMail({
    from: process.env.SMTP_FROM || '"MyPaidPost" <hello@mypaidpost.co.ke>',
    to: email,
    subject: 'Reset Your Password',
    text: `You are receiving this email because you (or someone else) requested a password reset for your MyPaidPost account.\n\nPlease click on the following link, or paste this into your browser: ${resetUrl}\n\nThis link will expire in 1 hour.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nThe MyPaidPost Team`,
    html: `<p>You are receiving this email because you (or someone else) requested a password reset for your MyPaidPost account.</p><p>Please click on the following link, or paste this into your browser: <a href="${resetUrl}">Reset Password</a></p><p>This link will expire in 1 hour.</p><p>If you did not request this, please ignore this email.</p><p>Best regards<br/>The MyPaidPost Team</p>`,
  });
};