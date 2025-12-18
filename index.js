const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

/* =======================
   Firebase Admin
======================= */
const serviceAccount = require('./city-care-89520-firebase-adminsdk.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

/* =======================
   Middleware
======================= */
app.use(cors());
app.use(express.json());

const verifyFBToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: 'Unauthorized' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = await admin.auth().verifyIdToken(token);
        req.email = decoded.email;
        next();
    } catch {
        res.status(401).send({ message: 'Unauthorized' });
    }
};

const verifyResolver = async (req, res, next) => {
    const staff = await staffs.findOne({
        userEmail: req.email,
        status: 'approved',
    });

    if (!staff) {
        return res.status(403).send({ message: 'Resolver access only' });
    }

    req.staff = staff;
    next();
};

/* =======================
   Helpers
======================= */
const generateTrackingId = () => {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const random = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `CC-${date}-${random}`;
};

/* =======================
   MongoDB
======================= */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.pscbpur.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    await client.connect();

    const db = client.db('city_care_db');
    const users = db.collection('users');
    const issues = db.collection('issues');
    const trackings = db.collection('trackings');
    const payments = db.collection('payments');
    const staffs = db.collection('staffs');
    const contact = db.collection('contact');

    /* =======================
       Role Middleware
    ======================= */
    const verifyAdmin = async (req, res, next) => {
        const user = await users.findOne({ email: req.email });
        if (!user || user.role !== 'admin') {
            return res.status(403).send({ message: 'Forbidden' });
        }
        next();
    };

    /* =======================
       Tracking Logger
    ======================= */
    const addTracking = async (trackingId, status, updatedBy) => {
        await trackings.insertOne({
            trackingId,
            status,
            updatedBy,
            createdAt: new Date(),
        });
    };

    /* =======================
       USERS
    ======================= */
    app.post('/users', async (req, res) => {
        const user = req.body;

        const exists = await users.findOne({ email: user.email });
        if (exists) {
            return res.send({ message: 'User already exists' });
        }

        const userDoc = {
            email: user.email,
            displayName: user.displayName,
            photoURL: user.photoURL,
            role: 'citizen', // ✅ default
            isPremium: false,
            createdAt: new Date(),
        };

        await users.insertOne(userDoc);

        res.send({ success: true });
    });

    app.get('/users', verifyFBToken, verifyAdmin, async (req, res) => {
        const { searchText = '' } = req.query;
        const query = {
            displayName: { $regex: searchText, $options: 'i' },
        };
        const allUsers = await users
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();
        res.send(allUsers);
    });

    app.get('/users/:email/role', async (req, res) => {
        const user = await users.findOne({ email: req.params.email });
        res.send({ role: user?.role || 'citizen' });
    });

    app.patch(
        '/users/:id/role',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const { role } = req.body;
            const { id } = req.params;

            // 1️⃣ validate role
            const allowedRoles = ['citizen', 'admin'];
            if (!allowedRoles.includes(role)) {
                return res.status(400).send({ message: 'Invalid role value' });
            }

            // 2️⃣ validate ObjectId
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: 'Invalid user id' });
            }

            const result = await users.updateOne(
                { _id: new ObjectId(id) },
                { $set: { role } }
            );

            if (result.matchedCount === 0) {
                return res.status(404).send({ message: 'User not found' });
            }

            res.send({
                success: true,
                message: `User role updated to ${role}`,
            });
        }
    );

    /* =======================
       ISSUES
    ======================= */

    app.post('/issues', verifyFBToken, async (req, res) => {
        try {
            const issue = req.body;
            issue.reportedBy = req.email;
            issue.trackingId = generateTrackingId();
            issue.createdAt = new Date();
            issue.upvotes = 0;
            issue.upvotedBy = [];
            issue.priority = issue.priority || 'normal';
            issue.status = 'pending';
            issue.tracking = [
                {
                    status: 'Issue Created',
                    message: 'Issue reported by citizen',
                    updatedBy: req.email,
                    createdAt: new Date(),
                },
            ];

            const result = await issues.insertOne(issue);
            res.send({ success: true, insertedId: result.insertedId });
        } catch (error) {
            console.error('❌ Issue Create Error:', error);
            res.status(500).send({
                success: false,
                message: 'Failed to create issue',
            });
        }
    });

    app.get('/issues', async (req, res) => {
        try {
            const { email, status, category, priority, search, limit } =
                req.query;

            let query = {};

            if (email) query.reportedBy = email;
            if (status) query.status = status;
            if (category) query.category = category;
            if (priority) query.priority = priority;

            if (search) {
                query.title = { $regex: search, $options: 'i' };
            }

            const result = await issues
                .find(query)
                .sort({
                    priority: priority === 'high' ? -1 : -1, // high first
                    upvotes: -1,
                    createdAt: -1,
                })
                .limit(Number(limit) || 0)
                .toArray();

            res.send(result);
        } catch (error) {
            console.error('❌ Get Issues Error:', error);
            res.status(500).send([]);
        }
    });

    // PATCH /issues/:id/upvote
    app.patch('/issues/:id/upvote', verifyFBToken, async (req, res) => {
        const { id } = req.params;
        const userEmail = req.email;

        try {
            const issue = await issues.findOne({ _id: new ObjectId(id) });
            if (!issue)
                return res.status(404).send({ message: 'Issue not found' });

            // Users cannot upvote their own issue
            if (issue.reportedBy === userEmail) {
                return res
                    .status(403)
                    .send({ message: 'Cannot upvote your own issue' });
            }

            const upvotedBy = issue.upvotedBy || [];

            // Toggle upvote (if already upvoted, remove)
            let updatedUpvotedBy;
            let upvoteCount;
            if (upvotedBy.includes(userEmail)) {
                updatedUpvotedBy = upvotedBy.filter(
                    (email) => email !== userEmail
                );
            } else {
                updatedUpvotedBy = [...upvotedBy, userEmail];
            }

            upvoteCount = updatedUpvotedBy.length;

            await issues.updateOne(
                { _id: new ObjectId(id) },
                { $set: { upvotes: upvoteCount, upvotedBy: updatedUpvotedBy } }
            );

            const updatedIssue = await issues.findOne({
                _id: new ObjectId(id),
            });
            res.send({ success: true, issue: updatedIssue });
        } catch (err) {
            console.error('Upvote Error:', err);
            res.status(500).send({ success: false, message: 'Upvote failed' });
        }
    });

    app.get('/issues/:id', verifyFBToken, async (req, res) => {
        const { id } = req.params;
        try {
            const issue = await issues.findOne({ _id: new ObjectId(id) });
            if (!issue)
                return res.status(404).send({ message: 'Issue not found' });

            res.send(issue);
        } catch (err) {
            console.error('Get Issue Error:', err);
            res.status(500).send({ message: 'Failed to fetch issue' });
        }
    });

    app.patch('/issues/:id', verifyFBToken, async (req, res) => {
        const issueId = req.params.id;
        const updates = req.body;
        const issue = await issues.findOne({ _id: new ObjectId(issueId) });
        if (!issue) return res.status(404).send({ error: 'Issue not found' });
        if (issue.reportedBy !== req.email)
            return res.status(403).send({ error: 'Unauthorized' });
        if (issue.status !== 'pending')
            return res
                .status(400)
                .send({ error: 'Cannot edit resolved/in-progress issue' });

        await issues.updateOne(
            { _id: new ObjectId(issueId) },
            {
                $set: updates,
                $push: {
                    tracking: {
                        status: 'Edited',
                        message: 'Issue edited by owner',
                        updatedBy: req.email,
                        createdAt: new Date(),
                    },
                },
            }
        );

        const updatedIssue = await issues.findOne({
            _id: new ObjectId(issueId),
        });
        res.send({ success: true, issue: updatedIssue });
    });

    app.delete('/issues/:id', verifyFBToken, async (req, res) => {
        const { id } = req.params;
        const userEmail = req.email;

        try {
            const issue = await issues.findOne({ _id: new ObjectId(id) });
            if (!issue)
                return res.status(404).send({ message: 'Issue not found' });

            // Only issue owner can delete
            if (issue.reportedBy !== userEmail) {
                return res.status(403).send({ message: 'Not authorized' });
            }

            await issues.deleteOne({ _id: new ObjectId(id) });
            res.send({ success: true });
        } catch (err) {
            console.error('Delete Issue Error:', err);
            res.status(500).send({
                success: false,
                message: 'Failed to delete issue',
            });
        }
    });

    app.patch('/issues/:id/status', verifyFBToken, async (req, res) => {
        const { status } = req.body;
        const issueId = req.params.id;

        const issue = await issues.findOne({ _id: new ObjectId(issueId) });
        if (!issue) return res.status(404).send({ error: 'Issue not found' });

        await issues.updateOne(
            { _id: issue._id },
            {
                $set: { status },
                $push: {
                    tracking: {
                        status:
                            status.charAt(0).toUpperCase() + status.slice(1),
                        message: `Issue marked as ${status}`,
                        updatedBy: req.role || 'Admin',
                        createdAt: new Date(),
                    },
                },
            }
        );

        res.send({ success: true, status });
    });

    /* =======================
       PAYMENTS
    ======================= */
    app.post('/create-checkout-session', async (req, res) => {
        const { cost, issueId, senderEmail, issueName } = req.body;
        try {
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                mode: 'payment',
                line_items: [
                    {
                        price_data: {
                            currency: 'bdt',
                            product_data: {
                                name: `Boost Priority: ${issueName}`,
                            },
                            unit_amount: cost * 100,
                        },
                        quantity: 1,
                    },
                ],
                metadata: { issueId, senderEmail, purpose: 'boost' },
                success_url: `${process.env.SITE_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.SITE_DOMAIN}/issue-details/${issueId}?boost=cancel`,
            });

            res.send({ url: session.url });
        } catch (err) {
            console.log(err);
            res.status(500).send({
                success: false,
                message: 'Failed to create session',
            });
        }
    });

    app.post(
        '/webhook',
        express.raw({ type: 'application/json' }),
        async (req, res) => {
            const sig = req.headers['stripe-signature'];
            let event;

            try {
                event = stripe.webhooks.constructEvent(
                    req.body,
                    sig,
                    process.env.STRIPE_WEBHOOK_SECRET
                );
            } catch (err) {
                console.log('Webhook signature verification failed', err);
                return res.status(400).send(`Webhook Error: ${err.message}`);
            }

            if (event.type === 'checkout.session.completed') {
                const session = event.data.object;
                const issueId = session.client_reference_id; // or custom field

                const issue = await issues.findOne({
                    _id: new ObjectId(issueId),
                });
                if (!issue)
                    return res.status(404).send({ message: 'Issue not found' });

                // Update priority & add timeline entry
                await issues.updateOne(
                    { _id: new ObjectId(issueId) },
                    {
                        $set: { priority: 'high' },
                        $push: {
                            tracking: {
                                status: 'boosted',
                                message: 'Issue boosted by payment',
                                updatedBy: session.customer_email,
                                createdAt: new Date(),
                            },
                        },
                    }
                );
            }

            res.status(200).send({ received: true });
        }
    );

    app.get('/payment-success', async (req, res) => {
        const session = await stripe.checkout.sessions.retrieve(
            req.query.session_id
        );

        if (session.payment_status !== 'paid') {
            return res.status(400).send({ success: false });
        }

        // Retrieve the issue first
        const issue = await issues.findOne({
            _id: new ObjectId(session.metadata.issueId),
        });

        // save payment
        await payments.insertOne({
            transactionId: session.payment_intent,
            issueId: session.metadata.issueId,
            issueName: issue.title, // add this
            trackingId: session.metadata.issueId, // or generate a tracking id
            customerEmail: session.metadata.senderEmail,
            amount: session.amount_total / 100,
            purpose: 'boost',
            paidAt: new Date(),
        });

        // update issue
        await issues.updateOne(
            { _id: new ObjectId(session.metadata.issueId) },
            {
                $set: { priority: 'high' },
                $push: {
                    tracking: {
                        status: 'Boosted',
                        message: 'Issue boosted via payment',
                        updatedBy: session.metadata.senderEmail,
                        createdAt: new Date(),
                    },
                },
            }
        );

        res.send({
            success: true,
            transactionId: session.payment_intent,
            trackingId: session.payment_intent,
            issueId: session.metadata.issueId,
        });
    });

    app.get('/payments', verifyFBToken, async (req, res) => {
        const user = await users.findOne({ email: req.email });
        const query = user.role === 'admin' ? {} : { customerEmail: req.email };

        const latestPayments = await payments
            .aggregate([
                { $match: query },
                { $sort: { paidAt: -1 } },
                {
                    $group: {
                        _id: '$issueId',
                        transactionId: { $first: '$transactionId' },
                        issueName: { $first: '$issueName' },
                        trackingId: { $first: '$trackingId' },
                        customerEmail: { $first: '$customerEmail' },
                        amount: { $first: '$amount' },
                        paidAt: { $first: '$paidAt' },
                    },
                },
                { $sort: { paidAt: -1 } },
            ])
            .toArray();

        res.send(latestPayments);
    });

    app.post('/payments/cashout/:id', verifyFBToken, async (req, res) => {
        const paymentId = req.params.id;
        const user = await users.findOne({ email: req.email });

        if (user.role !== 'admin') {
            return res
                .status(403)
                .send({ success: false, message: 'Forbidden' });
        }

        const result = await payments.updateOne(
            { _id: new ObjectId(paymentId) },
            { $set: { cashoutDone: true, cashoutAt: new Date() } }
        );

        if (result.modifiedCount > 0) {
            res.send({ success: true });
        } else {
            res.status(400).send({ success: false, message: 'Cashout failed' });
        }
    });

    /* =======================
       STAFFS / RESOLVERS
    ======================= */
    app.get('/staffs', verifyFBToken, verifyAdmin, async (req, res) => {
        const allStaffs = await staffs.find().sort({ createdAt: -1 }).toArray();
        res.send(allStaffs);
    });

    app.post('/staffs', verifyFBToken, async (req, res) => {
        const staff = req.body;
        staff.status = 'pending';
        staff.workStatus = 'available';
        staff.createdAt = new Date();

        const result = await staffs.insertOne(staff);
        res.send({ success: true, insertedId: result.insertedId });
    });

    app.post('/staffs/apply', verifyFBToken, async (req, res) => {
        const staff = req.body;

        // check already applied
        const exists = await staffs.findOne({ userEmail: req.email });
        if (exists) {
            return res.status(400).send({ message: 'Already applied' });
        }

        const staffDoc = {
            userEmail: req.email,
            name: staff.name,
            district: staff.district,
            phone: staff.phone,
            skills: staff.skills || [],
            status: 'pending',
            workStatus: 'available',
            appliedAt: new Date(),
        };

        await staffs.insertOne(staffDoc);

        res.send({ success: true, message: 'Application submitted' });
    });

    // ✅ THIS IS THE FIXED ROUTE
    app.patch(
        '/staffs/:id/status',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const { status } = req.body;
            if (!['approved', 'rejected'].includes(status)) {
                return res.status(400).send({ message: 'Invalid status' });
            }

            const result = await staffs.updateOne(
                { _id: new ObjectId(req.params.id) },
                {
                    $set: {
                        status,
                        approvedAt: status === 'approved' ? new Date() : null,
                    },
                }
            );

            res.send(result);
        }
    );

    /* =======================
       ASSIGN STAFF TO ISSUE
    ======================= */
    app.patch(
        '/issues/:id/assign',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const { staffEmail, staffName } = req.body;

            await issues.updateOne(
                { _id: new ObjectId(req.params.id) },
                {
                    $set: {
                        status: 'in-progress',
                        assignedStaff: {
                            email: staffEmail,
                            name: staffName,
                        },
                    },
                    $push: {
                        tracking: {
                            status: 'Staff Assigned',
                            updatedBy: 'Admin',
                            createdAt: new Date(),
                        },
                    },
                }
            );

            await staffs.updateOne(
                { userEmail: staffEmail },
                { $set: { workStatus: 'busy' } }
            );

            res.send({ success: true });
        }
    );

    app.get('/staffs/my-issues', verifyFBToken, async (req, res) => {
        const result = await issues
            .find({ assignedStaff: req.email })
            .toArray();
        res.send(result);
    });

    /* =======================
       CONTACT
    ======================= */
    app.post('/contact-messages', async (req, res) => {
        const message = {
            ...req.body,
            isRead: false,
            adminReply: '',
            repliedAt: null,
            createdAt: new Date(),
        };
        const result = await contact.insertOne(message);
        res.send(result);
    });

    app.get(
        '/contact-messages',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const messages = await contact
                .find()
                .sort({ createdAt: -1 })
                .toArray();
            res.send(messages);
        }
    );

    app.patch(
        '/contact-messages/read/:id',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const id = req.params.id;
            const result = await contact.updateOne(
                { _id: new ObjectId(id) },
                { $set: { isRead: true } }
            );
            res.send(result);
        }
    );

    app.patch(
        '/contact-messages/reply/:id',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const id = req.params.id;
            const { reply } = req.body;
            const result = await contact.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        adminReply: reply,
                        repliedAt: new Date(),
                        isRead: true,
                    },
                }
            );
            res.send(result);
        }
    );

    app.delete(
        '/contact-messages/:id',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const id = req.params.id;
            const result = await contact.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        }
    );

    app.get(
        '/contact-messages-unread-count',
        verifyFBToken,
        verifyAdmin,
        async (req, res) => {
            const count = await contact.countDocuments({ isRead: false });
            res.send({ count });
        }
    );

    /* =======================
       RESOLVER DASHBOARD
    ======================= */
    app.get(
        '/resolver/issues',
        verifyFBToken,
        verifyResolver,
        async (req, res) => {
            const result = await issues
                .find({ 'assignedStaff.email': req.email })
                .toArray();
            res.send(result);
        }
    );

    /* =======================
       TRACKING LOGS
    ======================= */
    app.get('/trackings/:trackingId/logs', async (req, res) => {
        const { trackingId } = req.params;
        const issue = await issues.findOne({ trackingId });
        if (!issue) return res.status(404).send([]);
        res.send(issue.tracking || []);
    });

    console.log('✅ City Care Server Ready');
}

run();

app.get('/', (req, res) => {
    res.send('City Care API Running');
});

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});
