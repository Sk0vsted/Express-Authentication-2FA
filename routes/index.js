const express = require('express');
const router = express.Router();
const authController = require('../controllers/controllers');
const worldController = require('../controllers/controllersworld');
const sqlite3 = require('better-sqlite3')

const db = new sqlite3('db/sampleAPI.db');

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

router.post('/register', authController.register);
router.post('/login', authController.login);

// router.get('/users/profile', authController.authenticateUser, authController.getProfile);
router.get('/users', authController.authenticateUser, worldController.getCities);

router.get('/continents', authController.authenticateUser, worldController.getContinents);
router.get('/countries', authController.authenticateUser, worldController.getCountries);
router.get('/cities', authController.authenticateUser, worldController.getCities);
router.get('/languages', authController.authenticateUser, worldController.getLanguages);
router.get('/getCityDetails', authController.authenticateUser, worldController.getCityDetails);
router.post('/addCity', authController.authenticateUser, worldController.addCity);

router.get('/users/profile', authController.authenticateUser, worldController.getContinents, worldController.getCountries, worldController.getCities, worldController.getLanguages, (req, res) => {
	const userEmail = req.user.email; // Get the user's email from JWT

	const stmt = db.prepare('SELECT email, bio, admin, two_factor_enabled FROM user WHERE email = ?');
	const user = stmt.get(userEmail);

	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}

	console.log("✅ Rendering profile.pug with user data:", user);

	res.render('profile', {
		title: 'Profile',
		subtitle: 'Your profile',
		user, // Now includes `two_factor_enabled`
		continents: res.locals.continents || [],
		countries: res.locals.countries || [],
		cities: res.locals.cities || [],
		languages: res.locals.languages || []
	});
});


module.exports = router;
