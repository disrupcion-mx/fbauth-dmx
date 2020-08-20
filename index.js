const admin = require("firebase-admin");
const Joi = require("@hapi/joi");
const schema = Joi.object({
  token: Joi.string().required(),
});

const init = (databaseURL, serviceAccount) => {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL,
  });
};

const fbAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization.replace("Bearer ", "");
    const decodedToken = await admin.auth().verifyIdToken(token);
    if (decodedToken) {
      req.email = decodedToken.email;
      req.fbUID = decodedToken.uid;
      req.userName = decodedToken.name;
      return next();
    }
    res.sendStatus(401);
  } catch (e) {
    console.log(e.stack);
    res.status(401).send("No tienes autorización para ejecutar esta acción");
  }
};

const token = async (req, res, next) => {
  if (req.headers.authorization) {
    const { error } = schema.validate(req.header.authorization);
    if (error) throw new Error("Firebase token is invalid");
    next();
  } else {
    return res.status(400).send("Firebase token missing");
  }
};

module.exports = { token, fbAuth, init };
