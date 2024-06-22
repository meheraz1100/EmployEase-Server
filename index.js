const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const port = process.env.PORT || 3000;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
// middleware
app.use(cors());
app.use(express.json());



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bgw1n6h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    // collections
    const servicesCollection = client.db('employEase').collection('services');
    const userCollection = client.db('employEase').collection('users')
    const paymentCollection = client.db('employEase').collection('payments')
    const messageCollection = client.db('employEase').collection('messages');
    const worksheetCollection = client.db('employEase').collection('worksheet');

    // service related api
    app.get('/services', async (req, res) => {
      const result = await servicesCollection.find().toArray();
      res.send(result);
    })

    // jwt related api
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '1h'
      });
      res.send({ token });
    })

    // middlewares 
    const verifyToken = (req, res, next) => {
      console.log('Inside verify token', req.headers.authorization);
      if(!req.headers.authorization){
        return res.status(401).send({ message: 'Unathorized access'})
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
          return res.status(401).send({ message: 'Unathorized access' })
        }
        req.decoded = decoded;
        next();
      })
    }

    // use verify admin after verify token
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === 'admin';
      if(!isAdmin){
        return res.status(403).send({ message: 'forbidden access' });
      }
    }

    app.get('/users/admin/:email', verifyToken, async (req, res ) => {
      const email = req.params.email;

      if(email !== req.decoded?.email){
        return res.status(403).send({ message: 'forbidden access' })
      }
      const query = { email: email};
      const user = await userCollection.findOne(query);
      let admin = false;
      if(user){
        admin = user?.role === 'admin';
      }
      res.send({admin});
    })

    app.get('/users/hr/:email', verifyToken, async(req, res) => {
      const email = req.params.email;

      if(email !== req.decoded?.email){
        return res.status(403).send({ message: 'forbidden access' })
      }
      const query = { email: email};
      const user = await userCollection.findOne(query);
      let hr = false;
      if(user){
        hr = user?.role === 'hr';
      }
      res.send({hr});
    })

    // users related api
    app.post('/users', async (req, res) => {
      const user = req.body;
      // insert email if user does not exist 
      // you can do this many ways ( 1. email unique, 2. upsert 3. simple checking)
      const query = { email: user.email };
      const existingUser = await userCollection.findOne(query);
      if(existingUser){
        return res.send({ message: 'user already exists', insertedId: null })
      }
      const result = await userCollection.insertOne(user);
      res.send(result);
    })


    app.get('/users', async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    })


    app.get('/users/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.findOne(query);
      res.send(result);
    })

    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if(email !== req.decoded.email) {
        return res.status(403).send({ message: 'unauthorized access'})
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let isAdmin = false;
      if(user){
        isAdmin = user?.role === 'admin';
      }
      res.send({ isAdmin });
    })

    // get employee only
    app.get('/employees', async (req, res) => {
      const query = { role: 'employee' }
      const result = await userCollection.find(query).toArray();
      res.send(result);
    })

    

    // admin api
    app.get('/users/:email', async (req, res) => {
      const email = req.params.email;
      const query = { email: email }
      const result = await userCollection.findOne(query);
      res.send(result);
    })

    // make employee from hr
    app.patch('/users/hr/:id', async (req, res) => {
      const id = req.params.id;
      console.log(id)
      const filter = { _id: new ObjectId(id)};
      const updatedDoc = {
        $set: {
          role: 'hr'
        }
      }
      const result = await userCollection.updateOne(filter, updatedDoc);
      res.send(result);
    })

    // make a admin from hr
    app.patch('/users/admin/:id', async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id)};
      const updatedDoc = {
        $set: {
          role: 'admin'
        }
      }
      const result = await userCollection.updateOne(filter, updatedDoc);
      res.send(result);
    })

    // update employee role with a single api
    app.patch('/users/update-role/:id', async (req, res) => {
      const id = req.params.id;
      console.log(id)
      const filter = { _id: new ObjectId(id)};
      const updatedDoc = {
        $set: {
          role: req.body.role
        }
      }
      const result = await userCollection.updateOne(filter, updatedDoc);
      res.send(result);
    })


    

    // verify a employee 
    app.patch('/employees/verify/:id', async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id)};
      const updatedDoc = {
        $set: {
          verify: 'true'
        }
      }
      const result = await userCollection.updateOne(filter, updatedDoc);
      res.send(result);
    })

    // fire a employee
    app.delete('/users/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.deleteOne(query);
      res.send(result);
    })
    // get a single employee data
    app.get('/employee-details/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.findOne(query);
      res.send(result);
    })

    // employee payment api
    app.get('/payment/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.findOne(query);
      res.send(result);
    })

    app.get('/payments/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if(req.params.email !== req.decoded?.email){
        return res.status(403).send({ message: 'forbidden access' })
      }
      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    })

    // store the payment ids
    app.post('/payments', async(req, res) => {
      const payment = req.body;
      const result = await paymentCollection.insertOne(payment);
      res.send(result);
    })


    // payment intent
    app.post('/create-payment-intent', async(req, res) => {
      const {price} = req.body;
      const amount = parseInt(price * 100);
      console.log(amount, 'amount inside intent');

      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types: ['card']
      })

      res.send({
        clientSecret: paymentIntent.client_secret
      })
    })

    // send message from website visitor
    app.post('/messages', async (req, res) => {
      const newMessage = req.body;
      console.log(newMessage);
      const result = await messageCollection.insertOne(newMessage);
      res.send(result);
    })

    // recieved message
    app.get('/messages', async(req, res) => {
      const result = await messageCollection.find().toArray();
      res.send(result);
    })

    // received worksheet from an employee
    app.post('/worksheet', async (req, res) => {
      const worksheet = req.body;
      const result = await worksheetCollection.insertOne(worksheet);
      res.send(result);
    })

    // get worksheet from database
    app.get('/worksheet', async (req, res) => {
      const result = await worksheetCollection.find().toArray();
      res.send(result);
    })

    



    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);






app.get('/', (req, res) => {
    res.send('EmployEase is running');
})

app.listen(port, () => {
    console.log(`EmployEase is listening on port ${port}`);
})