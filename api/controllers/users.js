const mongoose = require("mongoose");
const bcrypt = require("bcrypt"); // package to encrypt/hash passwords
const jwt = require("jsonwebtoken"); // package to create web token

// import user schema
const User = require("../models/user");
// import other schemas to delete user documents
const Subject = require("../models/subject");
const Resource = require("../models/resource");

/*
Convert to promise to be able to use await 
*/
const bcryptPassword = password =>
  new Promise((resolve, reject) => {
    bcrypt.hash(password, 10, (error, hash) => {
      if (error) {
        reject({
          message: "Something went wrong.",
          error
        });
      } else {
        resolve(hash);
      }
    });
  });

exports.userSignup = async (req, res, next) => {

    const {email,firstName,lastName,password} =  req.body;

  // check if email is already taken
  const user = await User.find({ email })
    .exec()
    .catch(e => {
      res.status(500).json({ error });
    });

  if (user.length >= 1) {
    return res.status(409).json({
      message: "email already exists"
    });
  } else {
    // encrypt/hash password with salting
    const hash = await bcryptPassword(password).catch(e =>
      res.status(500).json(e)
    );

    // create new user with email and password
    const user = new User({
      _id: new mongoose.Types.ObjectId(),
      firstName,
      lastName,
      email,
      password: hash
    });

    let savedUser = await user.save().catch(error => {
      res.status(500).json({
        message: "Something went wrong",
        error
      });
    });

    // create json web token
    let token = jwt.sign(
      {
        email: savedUser.email,
        userId: savedUser._id
      },
      process.env.JWT_KEY,
      {
        expiresIn: "10h"
      }
    );
    res.status(201).json({
      message: "user created",
      token,
      user: {
        ...savedUser,
        //hide password
        password:""
      }
    });
  }
};

exports.userLogin = (req, res, next) => {
  User.find({ email: req.body.email })
    .exec()
    .then(user => {
      // check if user email exists
      if (user.length < 1) {
        return res.status(401).json({
          message: "Auth failed"
        });
      }
      // check if user password is correct
      bcrypt.compare(req.body.password, user[0].password, (error, result) => {
        if (error) {
          return res.status(401).json({
            message: "Auth failed"
          });
        }
        // bcrypt.compare returns true or false
        if (result) {
          // create json web token
          let token = jwt.sign(
            {
              email: user[0].email,
              userId: user[0]._id
            },
            process.env.JWT_KEY,
            {
              expiresIn: "10h"
            }
          );
          return res.status(200).json({
            message: "Auth successful",
            token,
            user: {
              firstName: user[0].firstName,
              lastName: user[0].lastName,
              email: user[0].email,
              password: user[0].password,
              userId: user[0]._id
            }
          });
        }
        res.status(401).json({
          message: "Auth failed"
        });
      });
    })
    .catch(error => {
      res.status(500).json({
        message: "Something went wrong.",
        error
      });
    });
};

exports.userDelete = (req, res, next) => {
  Subject.deleteMany({ userId: req.params.userId }, err => {
    if (err) console.log(err);
    console.log("subjects deleted");
  });
  Resource.deleteMany({ userId: req.params.userId }, err => {
    if (err) console.log(err);
    console.log("resources deleted");
  });
  User.findByIdAndDelete(req.params.userId)
    .exec()
    .then(result => {
      res.status(200).json({
        message: "user deleted"
      });
    })
    .catch(error => {
      res.status(500).json({
        message: "Something went wrong.",
        error
      });
    });
};

exports.userGetById = (req, res, next) => {
  User.findById(req.params.userId)
    .select("email password") // only these fields
    .exec()
    .then(user => {
      if (user) {
        res.status(200).json({
          email: user.email,
          password: user.password
        });
      } else {
        res.status(404).json({
          message: "user not found"
        });
      }
    })
    .catch(error => {
      res.status(500).json({
        message: "Something went wrong.",
        error
      });
    });
};
