require('dotenv').config();

const { MongoClient } = require('mongodb');

const atlasURI = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true`;

const database = new MongoClient(atlasURI);

module.exports = { database };
