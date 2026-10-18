import ImageKit from "@imagekit/nodejs";
import { randomBytes } from "node:crypto";

export const getUploadAuth = async (req, res) => {
  try {
    const privateKey = process.env.IMAGEKIT_PRIVATE_KEY;
    const publicKey = process.env.IMAGEKIT_PUBLIC_KEY;
    const urlEndpoint = process.env.IMAGEKIT_URL_ENDPOINT || "https://ik.imagekit.io/answer";

    if (!privateKey || !publicKey) {
      return res.status(500).json({ message: "ImageKit configuration missing" });
    }

    const ik = new ImageKit({ privateKey, publicKey, urlEndpoint });
    const token = randomBytes(16).toString("hex");
    const expire = Math.floor(Date.now() / 1000) + 300; // 5 min short expiry
    const auth = ik.helper.getAuthenticationParameters(token, expire);

    res.status(200).json({
      publicKey,
      urlEndpoint,
      token: auth.token,
      expire: auth.expire,
      signature: auth.signature,
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to generate upload authentication" });
  }
};
