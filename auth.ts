import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import { sql } from "@vercel/postgres";
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';


async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0]
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.')
  }
}



export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [Credentials({
    async authorize(credentials) {
      // parse user credentials from login form
      const parsedCredentials = z
        .object({ email: z.string().email(), password: z.string().min(6) })
        .safeParse(credentials)

      if (parsedCredentials.success) {
        // get user credentials from login form
        const { email, password } = parsedCredentials.data;
        // get user credentials from the database
        const user = await getUser(email);
        // if there's no user return null
        if (!user) return null;
        // compare if the password are matching
        const passwordsMatch = await bcrypt.compare(password, user.password);
        
        if (passwordsMatch) return user;
      }

      console.log('Invalid credentials');
      return null;
    }
  })]
})