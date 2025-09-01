require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const PDFDocument = require('pdfkit'); // npm install pdfkit
const app = express();
app.use(cors({
    origin: "http://localhost:5500",
    credentials: true 
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/learnhub", {})
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Connection Error:", err));
const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    enrolledCourses: [{ courseName: String, progress: Number }],
    securityQuestion: { type: String, required: true },
    securityAnswer: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" } // <-- Added role
});
const User = mongoose.model("User", UserSchema);
const CourseSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: String,
    learning: [String],
    price: String,
    videos: [String] // <-- Add this line
});
const Course = mongoose.model("Course", CourseSchema);
const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "User session expired. Please login again." });
    }
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET || "secretKey");
        req.user = verified;
        next();
    } catch (error) {
        return res.status(401).json({ message: "Session expired. Please login again." });
    }
};
const isAdmin = async (req, res, next) => {
    const user = await User.findById(req.user.userId);
    if (user && user.role === "admin") {
        next();
    } else {
        res.status(403).json({ message: "Access denied. Admins only." });
    }
};
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.post("/register", async (req, res) => {
    try {
        const { name, email, password, securityQuestion, securityAnswer } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAnswer = await bcrypt.hash(securityAnswer, 10);
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            securityQuestion,
            securityAnswer: hashedAnswer,
            enrolledCourses: []
        });
        await newUser.save();
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: "Invalid email or password" });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || "secretKey", { expiresIn: "1h" });
        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "Lax",
            maxAge: 3600000 
        });
        // Include role in response
        res.json({ 
            message: "Login successful", 
            user: { name: user.name, email: user.email, role: user.role } 
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});
app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Logged out successfully" });
});
app.post("/update-profile", verifyToken, async (req, res) => {
    try {
        const { name } = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });
        user.name = name;
        await user.save();
        res.json({ message: "Profile updated successfully", name: user.name, email: user.email });
    } catch (error) {
        console.error("Profile Update Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({
            question: user.securityQuestion,
            message: "Answer the security question to reset your password."
        });
    } catch (error) {
        console.error("Error finding user:", error);
        res.status(500).json({ message: "Error finding user" });
    }
});
app.post("/validate-answer", async (req, res) => {
    const { email, securityAnswer } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const isMatch = await bcrypt.compare(securityAnswer, user.securityAnswer);
        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect answer" });
        }
        res.status(200).json({ message: "Answer validated. Proceed to reset your password." });
    } catch (error) {
        console.error("Error validating answer:", error);
        res.status(500).json({ message: "Error validating answer" });
    }
});
app.post("/reset-password", async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).json({ message: "Error resetting password" });
    }
});
app.post("/update-progress", verifyToken, async (req, res) => {
    try {
        const { courseName, watchedLessons, totalLessons } = req.body;
        if (!courseName) return res.status(400).json({ message: "Course name is required." });
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });
        const course = user.enrolledCourses.find(course => course.courseName === courseName);
        if (course) {
            const newProgress = Math.min((watchedLessons / totalLessons) * 100, 100);
            course.progress = newProgress;
            await user.save();
            res.json({ message: "Progress updated!", progress: newProgress });
        } else {
            res.status(404).json({ message: "Course not found in enrolled courses." });
        }
    } catch (error) {
        console.error("Progress Update Error:", error);
        res.status(500).json({ message: "Server Error." });
    }
});
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({ name: user.name, email: user.email, enrolledCourses: user.enrolledCourses });
    } catch (error) {
        console.error("Profile Fetch Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});
app.post("/enroll", verifyToken, async (req, res) => {
    try {
        const { courseName } = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });
        const courseExists = user.enrolledCourses.some(course => course.courseName === courseName);
        if (!courseExists) {
            user.enrolledCourses.push({ courseName, progress: 0 });
            await user.save();
        }
        res.json({ message: "Enrolled successfully", enrolledCourses: user.enrolledCourses });
    } catch (error) {
        console.error("Enrollment Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});
app.get("/course-details", async (req, res) => {
    const courseName = req.query.name;
    try {
        const course = await Course.findOne({ name: courseName });
        if (course) {
            res.json({
                title: course.name,
                description: course.description,
                learning: course.learning,
                price: course.price,
                videos: course.videos // <-- Make sure this is included
            });
        } else {
            res.status(404).json({ message: "Course not found" });
        }
    } catch (error) {
        res.status(500).json({ message: "Server error. Try again later." });
    }
});
app.get("/recommended-courses", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });
        const allCourses = await Course.find();
        const recommended = allCourses.filter(course =>
            !user.enrolledCourses.some(enrolled => enrolled.courseName === course.name)
        );
        res.json({ recommendedCourses: recommended });
    } catch (error) {
        res.status(500).json({ message: "Server error. Try again later." });
    }
});
app.post("/mark-complete", verifyToken, async (req, res) => {
    try {
        const { courseName } = req.body;
        if (!courseName) return res.status(400).json({ message: "Course name is required" });
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });
        const course = user.enrolledCourses.find(course => course.courseName === courseName);
        if (course) {
            course.progress = 100;
            await user.save();
            res.json({ message: "Course marked as complete!", progress: 100 });
        } else {
            res.status(404).json({ message: "Course not found in enrolled courses." });
        }
    } catch (error) {
        console.error("Progress Update Error:", error);
        res.status(500).json({ message: "Server Error. Try again later." });
    }
});
app.get("/courses", async (req, res) => {
    try {
        const courses = await Course.find();
        res.json(courses);
    } catch (error) {
        res.status(500).json({ message: "Server Error. Try again later." });
    }
});
// Admin: Create Course
app.post("/admin/course", verifyToken, isAdmin, async (req, res) => {
    try {
        const { name, description, learning, price, videos } = req.body;
        const course = new Course({ name, description, learning, price, videos });
        await course.save();
        res.json({ message: "Course created successfully", course });
    } catch (error) {
        res.status(500).json({ message: "Error creating course" });
    }
});

// Admin: Read All Courses
app.get("/admin/courses", verifyToken, isAdmin, async (req, res) => {
    try {
        const courses = await Course.find();
        res.json(courses);
    } catch (error) {
        res.status(500).json({ message: "Error fetching courses" });
    }
});

// Admin: Update Course
app.put("/admin/course/:id", verifyToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, learning, price } = req.body;
        const course = await Course.findByIdAndUpdate(id, { name, description, learning, price }, { new: true });
        res.json({ message: "Course updated", course });
    } catch (error) {
        res.status(500).json({ message: "Error updating course" });
    }
});

// Admin: Delete Course
app.delete("/admin/course/:id", verifyToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await Course.findByIdAndDelete(id);
        res.json({ message: "Course deleted" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting course" });
    }
});
app.get("/certificate", verifyToken, async (req, res) => {
    const courseName = req.query.course;
    try {
        const user = await User.findById(req.user.userId);
        const enrolled = user.enrolledCourses.find(c => c.courseName === courseName);
        if (!enrolled || enrolled.progress < 100) {
            return res.status(403).json({ message: "Course not completed." });
        }
        const doc = new PDFDocument({ size: 'A4', margin: 50 });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${courseName}-certificate.pdf`);

        // Background color
        doc.rect(0, 0, doc.page.width, doc.page.height).fill('#f7f6fa');

        // Decorative border
        doc.save()
            .lineWidth(4)
            .strokeColor('#6c47a3')
            .rect(20, 20, doc.page.width - 40, doc.page.height - 40)
            .stroke()
            .restore();

        // Logo (centered at the top)
        const logoWidth = 100;
        const logoHeight = 100;
        const logoX = (doc.page.width - logoWidth) / 2;
        doc.image(path.join(__dirname, 'public', 'images', 'log.jpeg'), logoX, 40, { width: logoWidth, height: logoHeight });

        // Move below logo
        doc.y = 160;

        // Platform name
        doc.fontSize(32).fillColor('#6c47a3').font('Helvetica-Bold')
            .text('LearnHub', { align: 'center', underline: true });

        // Certificate title
        doc.moveDown(0.5);
        doc.fontSize(26).fillColor('#333').font('Helvetica-Bold')
            .text('Certificate of Completion', { align: 'center' });

        // Decorative line
        doc.moveDown(0.3);
        doc.moveTo(100, doc.y).lineTo(doc.page.width - 100, doc.y).strokeColor('#6c47a3').lineWidth(2).stroke();

        // Recipient
        doc.moveDown(0.8);
        doc.fontSize(18).fillColor('#222').font('Helvetica')
            .text(`This is to certify that`, { align: 'center' });
        doc.moveDown(0.3);
        doc.fontSize(24).fillColor('#6c47a3').font('Helvetica-Bold')
            .text(user.name, { align: 'center' });

        // Course name
        doc.moveDown(0.3);
        doc.fontSize(18).fillColor('#222').font('Helvetica')
            .text(`has successfully completed the course`, { align: 'center' });
        doc.moveDown(0.3);
        doc.fontSize(22).fillColor('#6c47a3').font('Helvetica-Bold')
            .text(courseName, { align: 'center' });

        // Date
        doc.moveDown(0.8);
        doc.fontSize(14).fillColor('#555').font('Helvetica')
            .text(`Date: ${new Date().toLocaleDateString()}`, { align: 'center' });

        // Decorative line
        doc.moveDown(0.8);
        doc.moveTo(100, doc.y).lineTo(doc.page.width - 100, doc.y).strokeColor('#6c47a3').lineWidth(2).stroke();

        // Team name
        doc.moveDown(0.5);
        doc.fontSize(16).fillColor('#333').font('Helvetica-Bold')
            .text('LearnHub Team', { align: 'center' });

        // Footer (keep at bottom, not too low)
        doc.fontSize(10).fillColor('#aaa').font('Helvetica')
            .text('This certificate is generated by LearnHub for successful course completion.', 50, doc.page.height - 80, {
                align: 'center',
                width: doc.page.width - 100
            });

        doc.end();
        doc.pipe(res);
    } catch (error) {
        res.status(500).json({ message: "Error generating certificate." });
    }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
