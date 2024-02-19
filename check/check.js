const mineflayer = require('mineflayer');

const ip = process.argv[2];
const connectTimeout = setTimeout(() => {
  process.exit(1);
}, 3000);

try {
  const bot = mineflayer.createBot({
    host: ip,
    port: 25565,
    hideErrors: true,
    username: 'BetterHeimer'
  });

  bot.on('spawn', () => {
    clearTimeout(connectTimeout);
    bot.quit();
    process.exit(0)
  });
} catch (error) {}