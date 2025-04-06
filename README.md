# KhataBook Application

A web-based financial transaction management system. Track, manage, and share your financial records securely.

## Features

- User authentication and profile management
- Create and manage financial records ("hisabs")
- Add transactions (credit/debit)
- Encrypt sensitive financial records
- Share records with others via unique links
- Dark/light mode theming
- Filtering and sorting capabilities

## Deployment to Vercel

### Prerequisites

1. [GitHub account](https://github.com)
2. [Vercel account](https://vercel.com) (you can sign up with your GitHub account)
3. [MongoDB Atlas account](https://www.mongodb.com/cloud/atlas) for database

### Deployment Steps

1. **Push your code to GitHub**
   ```
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/khatabook-v2.git
   git push -u origin main
   ```

2. **Set up MongoDB Atlas**
   - Create a new cluster
   - Set up a database user with password
   - Allow network access from anywhere (or Vercel's IP range)
   - Get your connection string

3. **Deploy to Vercel**
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your GitHub repository
   - Configure project:
     - Framework Preset: `Other`
     - Build Command: `npm run vercel-build`
     - Output Directory: (leave empty)
     - Install Command: `npm install`
   - Add Environment Variables (from your .env file):
     - `MONGODB_URI`: Your MongoDB connection string
     - `BASE_URL`: Will be automatically set by Vercel
     - `JWT_SECRET`: Set a strong secret key
     - `SESSION_SECRET`: Set a strong secret key
     - `NODE_ENV`: Set to `production`
   - Click "Deploy"

4. **After Deployment**
   - Update your `.env` file with the new Vercel deployment URL
   - Any future pushes to your GitHub repository will auto-deploy

## Local Development

1. Clone the repository
2. Install dependencies with `npm install`
3. Create a `.env` file based on `.env.example`
4. Run the application with `npm run dev`
5. Access the application at `http://localhost:3000`

## Environment Variables

- `BASE_URL`: Base URL of your application
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT token signing
- `SESSION_SECRET`: Secret key for express-session
- `NODE_ENV`: Current environment (development/production) 