const express = require('express');
const router = new express.Router();
const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { username, password } = req.body;

  if (!password || !username) {
    next(new Error('Cannot be an empty field.'));
    return;
  }

  bcryptjs
    .hash(password, 10)
    .then((passwordHashAndSalt) => {
      return User.create({ username, passwordHashAndSalt });
    })
    .then((user) => {
      res.session.userId = user._id;
      res.redirect('/');
    })
    .catch((error) => next(error));
});

router.get('/login', (req, res, next) => {
  res.render('login');
});

router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (!password || !username) {
    next(new Error('Cannot be an empty field.'));
    return;
  }

  let user;
  User.findOne({ username })
    .then((_user) => {
      if (!_user)
        return Promise.reject(
          new Error('There is no user with that username.')
        );

      user = _user;
      return bcryptjs.compare(password, _user.passwordHashAndSalt);
    })
    .then((result) => {
      if (!result) return Promise.reject(new Error('Wrong password.'));

      req.session.userId = user._id;
      res.redirect('/private');
    })
    .catch((error) => next(error));
});

// router.get('/private', routeGuard, (req, res, next) => {
//   res.render('private');
// });

// router.get('/main', routeGuard, (req, res, next) => {
//   res.render('main');
// });

module.exports = router;
