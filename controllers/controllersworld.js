const models = require('../models/dbhandlers');
const sqlite3 = require('better-sqlite3');
const jwt = require('jsonwebtoken');

const db = new sqlite3('db/sampleAPI.db');

// ✅ Middleware: Verificér JWT token
async function authenticateUser(req, res, next) {
	const token = req.cookies.jwt;
	if (!token) {
		return res.status(401).json({ error: 'Access Denied: No Token Provided!' });
	}

	try {
		const decoded = jwt.verify(token, process.env.SECRET);
		req.user = decoded;
		next();
	} catch (error) {
		return res.status(400).json({ error: 'Invalid Token' });
	}
}

// ✅ Hent liste over kontinenter
async function getContinents(req, res, next) {
	let rows = await models.getAllContinents(req, res, next);
	res.locals.continents = rows;
	next();
}

// ✅ Hent liste over lande
async function getCountries(req, res, next) {
	let rows = await models.getAllCountries(req, res, next);
	res.locals.countries = rows;
	next();
}

// ✅ Hent liste over byer
async function getCities(req, res, next) {
	let rows = await models.getAllCities(req, res, next);
	res.locals.cities = rows;
	next();
}

// ✅ Hent liste over sprog
async function getLanguages(req, res, next) {
	let rows = await models.getAllLanguages(req, res, next);
	res.locals.languages = rows;
	next();
}

// ✅ Hent detaljer om en by
function getCityDetails(req, res) {
	const cityId = req.query.cityName;

	if (!cityId) {
		return res.status(400).json({ error: 'Missing city ID' });
	}

	const stmt = db.prepare('SELECT name, countrycode, district, population FROM city WHERE name = ?');
	const city = stmt.get(cityId);

	if (!city) {
		return res.status(404).json({ error: 'City not found' });
	}

	res.json(city);
}

// ✅ Tilføj en ny by
async function addCity(req, res, next) {
	const { name, countrycode, district, population } = req.body;

	if (!name || !countrycode || !district || !population) {
		return res.status(400).json({ error: 'Missing required fields' });
	}

	const stmt = db.prepare('INSERT INTO city (name, countrycode, district, population) VALUES (?, ?, ?, ?)');
	stmt.run(name, countrycode, district, population);

	console.log(`🏙️ City added: ${name}, ${countrycode}, ${district}, ${population}`);
	res.redirect('/users/profile');
}

module.exports = {
	authenticateUser,
	getContinents,
	getCountries,
	getCities,
	getLanguages,
	getCityDetails,
	addCity
};
