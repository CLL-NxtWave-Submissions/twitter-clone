const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const SALT_ROUNDS_FOR_PASSWORD_HASHING = 10;
const AUTHORIZATION_SECRET_FOR_JWT = "AUTHORIZATION_KEY";

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
    Function Name   : isExistingUser
    Input Parameter : inputUsername
    Return Value    : Boolean true for existing user
                      and false otherwise
    -------------------------------------------------
    Description: Function to check if a user exists
                 with the given username.
*/
const isExistingUser = async (inputUsername) => {
  let existingUserCheckResult = {
    userExists: true,
    existingUserData: {},
  };

  const queryToFetchExistingUserData = `
    SELECT
        *
    FROM
        user
    WHERE
        username = '${inputUsername}';
    `;

  const existingUserDataFromDB = await twitterCloneDBConnectionObj.get(
    queryToFetchExistingUserData
  );

  if (existingUserDataFromDB !== undefined) {
    existingUserCheckResult.existingUserData = existingUserDataFromDB;
  } else {
    existingUserCheckResult.userExists = false;
  }

  return existingUserCheckResult;
};

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

  const userCheckResult = await isExistingUser(inputUsername);
  if (userCheckResult.userExists) {
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
    Function Name         : verifyLoginPassword
    Input Parameters      :
        - inputUsername   : Input username to fetch
                            existing user data
        - inputPassword   : Input password to compare
                            with hashed password stored
                            in the database for existing
                            user
    Return Value          : Validation Result Object
        - isValidPassword : Boolean true for valid
                            password and false otherwise
        - failedMsg       : Failed validation message
    -----------------------------------------------------
    Description: Function to validate input
                 password and accordingly
                 return the result in an object.
*/
const verifyLoginCredentials = async (inputUsername, inputPassword) => {
  const loginCredentialsCheckResult = {
    isUsernameValid: true,
    isPasswordValid: true,
  };

  const userCheckResult = await isExistingUser(inputUsername);
  if (!userCheckResult.userExists) {
    loginCredentialsCheckResult.isUsernameValid = false;
    loginCredentialsCheckResult.isPasswordValid = false;
  } else {
    // valid username
    const userDataFromDB = userCheckResult.existingUserData;
    const hashedPassword = userDataFromDB.password;

    let isMatchingPassword = await bcrypt.compare(
      inputPassword,
      hashedPassword
    );
    if (!isMatchingPassword) {
      loginCredentialsCheckResult.isPasswordValid = false;
    }
  }

  return loginCredentialsCheckResult;
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

/*
    End-Point 2: POST /login
    ------------
    To login a user based on 
    input credentials, after
    verification of the same
*/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const loginCredentialsCheckResult = await verifyLoginCredentials(
    username,
    password
  );
  if (!loginCredentialsCheckResult.isUsernameValid) {
    res.status(400);
    res.send("Invalid user");
  } else if (!loginCredentialsCheckResult.isPasswordValid) {
    res.status(400);
    res.send("Invalid password");
  } else {
    // login success !
    const userIdentifiablePayload = { username };
    const jwtToken = jwt.sign(
      userIdentifiablePayload,
      AUTHORIZATION_SECRET_FOR_JWT
    );
    res.send({ jwtToken });
  }
});

/*
    End-Point 3  : GET /user/tweets/feed
    Header Name  : Authorization
    Header Value : Bearer JSON_WEB_TOKEN
    --------------
    To fetch latest 4 tweets posted by
    users followed by the logged in user

*/
app.get("/user/tweets/feed", async (req, res) => {
  const authorizationHeaderValue = req.headers.authorization;
  if (authorizationHeaderValue === undefined) {
    res.status(401);
    res.send("Invalid JWT Token");
  } else {
    const jsonWebTokenFromAuthHeader = authorizationHeaderValue.split(" ")[1];
    jwt.verify(
      jsonWebTokenFromAuthHeader,
      AUTHORIZATION_SECRET_FOR_JWT,
      async (verificationError, userIdentifiablePayload) => {
        if (verificationError) {
          res.status(401);
          res.send("Invalid JWT Token");
        } else {
          const { username } = userIdentifiablePayload;
          const queryToFetchLoggedInUserDetails = `
                SELECT *
                FROM user
                WHERE username = '${username}';
                `;

          const loggedInUserDetails = await twitterCloneDBConnectionObj.get(
            queryToFetchLoggedInUserDetails
          );
          const { user_id } = loggedInUserDetails;

          const queryToFetchFollowingUserIDs = `
                SELECT
                    following_user_id
                FROM
                    follower
                WHERE
                    follower_user_id = ${user_id};
                `;

          const listOfFollowingUserIdObjects = await twitterCloneDBConnectionObj.all(
            queryToFetchFollowingUserIDs
          );

          const listOfFollowingUserIds = listOfFollowingUserIdObjects.map(
            (currentFollowingUserIdObject) =>
              currentFollowingUserIdObject.following_user_id.toString()
          );

          const followingUserIdsString = listOfFollowingUserIds.join(", ");

          const queryToFetchLatest4TweetsFromFollowingUserIds = `
          SELECT
            user.username AS username,
            tweet.tweet AS tweet,
            tweet.date_time AS date_time
          FROM 
            tweet
          INNER JOIN 
            user
          ON
            tweet.user_id = user.user_id
          WHERE
            tweet.user_id IN (${followingUserIdsString})
          ORDER BY
            tweet.date_time
          LIMIT 4;
          `;

          const latest4TweetsFromFollowingUserIds = await twitterCloneDBConnectionObj.all(
            queryToFetchLatest4TweetsFromFollowingUserIds
          );
          const processedLatest4TweetsFromFollowingUserIds = latest4TweetsFromFollowingUserIds.map(
            (currentTweet) => ({
              username: currentTweet.username,
              tweet: currentTweet.tweet,
              dateTime: currentTweet.date_time,
            })
          );
          res.send(processedLatest4TweetsFromFollowingUserIds);
        }
      }
    );
  }
});

module.exports = app;
