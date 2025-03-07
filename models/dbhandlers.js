const path = require('path');
const sqlite3 = require("better-sqlite3");

// Start db connection
const connect = async function () {
	try {
		const db = await new sqlite3(path.resolve('db/sampleAPI.db'), {fileMustExist: true});
		return db;
	} catch (err) {
			console.error(err);
	}
};

module.exports = {
	getAllContinents: async function (req, res, next) {
		try {
			let db = await connect();
			let sql = 'select * from continent';
			let query = db.prepare(sql);
			let rows = await query.all();
			return rows;
		} catch (err) {
			res.status(400).json(err.message);
		}
	},

	getAllCountries: async function (req, res, next) {
		try {
			let db = await connect();
			let sql = 'select * from country';
			let query = db.prepare(sql);
			let rows = await query.all();
			return rows;
		} catch (err) {
			res.status(400).json(err.message);
		}
	},

	getAllCities: async function (req, res, next) {
		try {
			let db = await connect();
			let sql = 'select * from city';
			let query = db.prepare(sql);
			let rows = await query.all();
			return rows;
		} catch (err) {
			res.status(400).json(err.message);
		}
	},

	getAllLanguages: async function (req, res, next) {
		try {
			let db = await connect();
			let sql = 'select * from countrylanguage';
			let query = db.prepare(sql);
			let rows = await query.all();
			return rows;
		} catch (err) {
			res.status(400).json(err.message);
		}
	}

}
