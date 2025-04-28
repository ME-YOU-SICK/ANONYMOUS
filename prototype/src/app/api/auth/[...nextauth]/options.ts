import { prisma } from "@/config/prismaConfig";
import bcryptjs from "bcryptjs";
import { NextAuthOptions } from "next-auth";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import CredentialsProvider from "next-auth/providers/credentials";
import { signinSchema } from "@/lib/validations/validations";

if (!process.env.NEXTAUTH_URL) {
  console.warn("Please set NEXTAUTH_URL environment variable");
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials) throw new Error("Credentials not provided");
        const { email, password } = credentials;

        const { success } = signinSchema.safeParse({ email, password });
        if (!success) throw new Error("Invalid credentials");

        try {
          const user = await prisma.user.findFirst({
            where: {
              email: email,
            },
          });

          if (!user) throw new Error("No user found with this email address");
          if (!password) throw new Error("Password is required");
          if (!user.password)
            throw new Error(
              "This email is registered with a Google account, please sign in with Google"
            );

          const isPasswordValid = await bcryptjs.compare(
            password,
            user.password!
          );
          if (!isPasswordValid) throw new Error("Invalid password");

          return {
            id: user.id,
            email: user.email,
            name: user.name || undefined,
          };
        } catch (error) {
          console.error("Authentication error:", error);
          throw error;
        }
      },
    }),
  ],
  adapter: PrismaAdapter(prisma),
  callbacks: {
    async jwt({ token, user, account }) {
      if (account?.access_token) {
        token.accessToken = account.access_token;
      }
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.email = token.email as string;
        session.user.name = token.name as string;
      }
      return session;
    },
  },
  pages: {
    signIn: "/signin",
    error: "/error",
  },
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  debug: true,
  secret: process.env.NEXTAUTH_SECRET,
};
