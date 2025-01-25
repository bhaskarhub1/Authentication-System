import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.json({
      success: false,
      message: "You are not authorized. Login again",
    });
  }

  try {
    const token_decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (token_decoded.id) {
      req.body.userId = token_decoded.id;
    } else {
      return res.json({
        success: false,
        message: "Not Authorized. Login Again",
      });
    }

    next();
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export default userAuth;
