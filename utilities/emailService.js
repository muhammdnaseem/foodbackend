import nodemailer from 'nodemailer';

// Create a transporter object using SMTP transport
const transporter = nodemailer.createTransport({
    service: 'gmail', // or your preferred email service
    auth: {
        user: process.env.GMAIL_USER, // Your email from env
        pass: process.env.GMAIL_PASS, // Your app-specific password or email password
    },
});

// Function to send verification email
const sendVerificationEmail = async (email, verificationToken) => {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify?token=${verificationToken}`; // Use environment variable for frontend URL

    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Email Verification',
        text: `Please verify your email by clicking on the following link: ${verificationUrl}`,
        // You can also use HTML for a more styled email
        // html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">${verificationUrl}</a></p>`,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Verification email sent successfully');
    } catch (error) {
        console.error('Error sending verification email:', error);
    }
};

export { sendVerificationEmail };
