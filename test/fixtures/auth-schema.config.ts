import { betterAuth } from "better-auth";
import { admin, emailOTP, phoneNumber, twoFactor, username } from "better-auth/plugins";
import { passwordPolicy } from "../../src/index.ts";

export const auth = betterAuth({
  baseURL: "http://localhost:3000",
  secret: "schema-generation-secret-0123456789abcde",
  emailAndPassword: { enabled: true },
  plugins: [
    admin(),
    username(),
    phoneNumber({ sendOTP: async () => {} }),
    emailOTP({ sendVerificationOTP: async () => {} }),
    twoFactor(),
    passwordPolicy(),
  ],
});
