import jwt from "jsonwebtoken";
export const requireToken = (req, res, next) => {
  try {
    let token = req.headers.authorization;
    if (!token) throw new Error("No existe el token en el header");

    token = token.split(" ")[1];
    const { uid } = jwt.verify(token, process.env.JWT_SECRET);

    req.uid = uid;

    next();
  } catch (error) {
    console.log(error);

    const tokenVerificationErrors = {
      "invalid signature": "La firma del JWT no es válido",
      "jwt expired": "JWT expirador",
      "invalid token": "Token no válido",
      "No Bearer": "Utiliza formato Bearer",
      "jwt malformed": "JWT formato no válido",
    };

    return res
      .status(401)
      .json({ error: tokenVerificationErrors[error.message] });
  }
};
