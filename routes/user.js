const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const {
  loginRules,
  registerRules,
  validation,
} = require("../middleware/validator");
const isAuth = require("../middleware/passport");
//router.get("/",(req, res)=>{
//res.send("hello world");
//});

// register
router.post("/register", registerRules(), validation, async (req, res) => {
  const { name, lastName, email, password } = req.body;
  try {
    const newUser = new User({ name, lastName, email, password });
    // check email existing
    const searchedUser = await User.findOne({ email });
    if (searchedUser) {
      return res.status(400).send({ msg: "email is already exist" });
    }

    //hash password
    const salt = 10;
    const genSalt = await bcrypt.genSalt(salt);
    const hashedPassword = await bcrypt.hash(password, genSalt);
    console.log(hashedPassword);
    newUser.password = hashedPassword;
    //generate token

    // save the user
    const newUserToken = await newUser.save();
    const payload = {
      _id: newUserToken._id,
      name: newUserToken.name,
    };
    const token = jwt.sign(payload, process.env.SecretOrKey, {
      expiresIn: 3600,
    });
    res.status(200).send({
      user: newUserToken,
      msg: "user is saved",
      token: `Bearer ${token}`,
    });
  } catch (error) {
    res.status(500).send(error);
  }
});
//login
router.post("/login", loginRules(), validation, async (req, res) => {
  const { email, password } = req.body;
  try {
    // find if the user exist
    const searchedUser = await User.findOne({ email });
    // if the email not exist
    if (!searchedUser) {
      return res.status(400).send({ msg: "bad Credential" });
    }
    // password are equals
    const match = await bcrypt.compare(password, searchedUser.password);
    if (!match) {
      return res.status(400).send({ msg: "bad Credential" });
    }
    // cree un token
    const payload = {
      _id: searchedUser._id,
      name: searchedUser.name,
    };
    const token = jwt.sign(payload, process.env.SecretOrkey, {
      expiresIn: 3600,
    });

    // send the user
    res
      .status(200)
      .send({ searchedUser, msg: "success", token: `Bearer ${token}` });
  } catch (error) {
    res.status(500).send({ msg: "can not get the user" });
  }
});

router.get("/current", isAuth(), (req, res) => {
  res.status(200).send({ user: req.user });
});
module.exports = router;
