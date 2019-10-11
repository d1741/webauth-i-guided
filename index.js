const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  // console.log("Password arriving from client: ", user.password);
  user.password = bcrypt.hashSync(user.password, 7);
  // console.log("Password heading to db: ", user.password);

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password, 6)) {
        // console.log("db password: ", user.password);
        // console.log("user password literal: ", password);
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
  //get username and password out of req headers (BAD BAD BAD in real life)
  const { username, password } = req.headers;
  //if successful, follow basic setup of login fx:
  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        //need to see if the user exists and the pwords match:
        if (user && bcrypt.compareSync(password, user.password)) {
          //we need to send the program to the next step:
          next();
        } else {
          //if there are issues with username/pword, we can kill the process:
          res.status(401).json({ message: "invalid credentials" });
        }
      })
      .catch(error => {
        //standard catch message:
        res.status(500).json({ message: "Unexpected error" });
      });
  } else {
    //send this back if pword/username grab is unsuccessful:
    res.status(400).json({ message: "Please provide username and password" });
  }
}

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
