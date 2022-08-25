const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const SALT_ROUNDS_FOR_PASSWORD_HASHING = 10;

const twitterCloneDatabaseFilePath = path.join(__dirname, "twitterClone.db");
const sqliteDriver = sqlite3.Database;

let twitterCloneDBConnectionObj = null;

const initializeDBAndServer = async () => {
  try {
    twitterCloneDBConnectionObj = await open({
      filename: twitterCloneDatabaseFilePath,
      driver: sqliteDriver,
    });

    app.listen(3000, () => {
      console.log("Server running and listening on port 3000 !");
      console.log("Base URL - http://localhost:3000");
    });
  } catch (exception) {
    console.log(`Error initializing database or server: ${exception.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

/*
    Function Name   : validateUsername
    Input Parameter : inputUsername
    Return Value    : Validation Result Object
        - isNewUser : Boolean true for new user
                      and false otherwise
        - failedMsg : Failed validation message
    --------------------------------------------
    Description: Function to validate input
                 username and accordingly
                 return the result in an object.
*/
const validateUsername = async (inputUsername) => {
  let validationResult = {
    isNewUser: true,
    failedMsg: "",
  };

  const queryToFetchExistingUserData = `
    SELECT
        *
    FROM
        user
    WHERE
        username = '${inputUsername}';
    `;

  const existingUserData = await twitterCloneDBConnectionObj.get(
    queryToFetchExistingUserData
  );
  if (existingUserData !== undefined) {
    validationResult.isNewUser = false;
    validationResult.failedMsg = "User already exists";
  }

  return validationResult;
};

/*
    Function Name         : validatePassword
    Input Parameter       : inputPassword
    Return Value          : Validation Result Object
        - isValidPassword : Boolean true for valid
                            password and false otherwise
        - failedMsg       : Failed validation message
    -----------------------------------------------------
    Description: Function to validate input
                 password and accordingly
                 return the result in an object.
*/
const validatePassword = (inputPassword) => {
  let validationResult = {
    isValidPassword: true,
    failedMsg: "",
  };

  if (inputPassword.length < 6) {
    validationResult.isValidPassword = false;
    validationResult.failedMsg = "Password is too short";
  }

  return validationResult;
};

/*
    End-Point 1: POST /register
    ------------
    To register/add new user
    to the user table with
    checks in place to validate
    input username and password
*/
app.post("/register", async (req, res) => {
  const { username, password, name, gender } = req.body;

  const usernameValidationResult = await validateUsername(username);

  if (!usernameValidationResult.isNewUser) {
    res.status(400);
    res.send(usernameValidationResult.failedMsg);
  } else {
    const passwordValidationResult = validatePassword(password);

    if (!passwordValidationResult.isValidPassword) {
      res.status(400);
      res.send(passwordValidationResult.failedMsg);
    } else {
      const hashedPassword = await bcrypt.hash(
        password,
        SALT_ROUNDS_FOR_PASSWORD_HASHING
      );

      const queryToAddNewUser = `
        INSERT INTO
            user (username, password, name, gender)
        VALUES
            ('${username}', '${hashedPassword}', '${name}', '${gender}');
        
        `;

      const addNewUserDBResponse = await twitterCloneDBConnectionObj.run(
        queryToAddNewUser
      );

      res.send("User created successfully");
    } // End of else-part of inner if-statement with condition: (!passwordValidationResult.isValidPassword)
  } // End of else-part of outer if-statement with condition: (!usernameValidationResult.isNewUser)
});

module.exports = app;
