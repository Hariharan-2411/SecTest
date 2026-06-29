module.exports = {
  testEnvironment: 'jest-environment-jsdom',
  testMatch: ['<rootDir>/tests/**/*.test.js'],
  transform: {
    '^.+\\.(js|jsx)$': 'babel-jest',
  },
  clearMocks: true,
};
