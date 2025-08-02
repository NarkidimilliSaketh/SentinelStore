# --- Stage 1: Build the React application ---
# Use a specific, stable version of Node.js on Alpine Linux for a smaller image
FROM node:18-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json (or yarn.lock, etc.) first
# This leverages Docker's layer caching. If these files don't change,
# Docker won't re-run 'npm install' on subsequent builds.
COPY package*.json ./

# Install all project dependencies
RUN npm install

# Copy the rest of the application source code
COPY . .

# Build the application for production.
# This command runs 'tsc' and 'vite build', creating an optimized build
# in the /app/dist folder.
RUN npm run build


# --- Stage 2: Serve the application using a lightweight Nginx server ---
# Use the official, stable Nginx image based on Alpine Linux
FROM nginx:stable-alpine

# Copy the built static files from the 'builder' stage to the default Nginx html directory
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy your custom Nginx configuration file.
# This is crucial for handling client-side routing in a Single-Page Application (SPA).
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80, which is the default port Nginx listens on inside the container
EXPOSE 80

# The default Nginx command starts the server in the foreground, which is correct for Docker.
# We specify it here for clarity.
CMD ["nginx", "-g", "daemon off;"]