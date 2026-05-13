import React, { useState, useEffect } from 'react';

const charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>";

const DecryptedText = ({ text, speed = 40, maxIterations = 15, className = "" }) => {
  const [displayText, setDisplayText] = useState(text.replace(/./g, ' '));
  const [iteration, setIteration] = useState(0);

  useEffect(() => {
    let currentIteration = 0;
    const interval = setInterval(() => {
      setDisplayText(prev => 
        text.split('').map((char, index) => {
          if (char === ' ') return ' ';
          if (index < currentIteration) {
            return text[index];
          }
          return charSet[Math.floor(Math.random() * charSet.length)];
        }).join('')
      );
      
      if (currentIteration >= text.length) {
        clearInterval(interval);
      }
      
      currentIteration += 1 / (maxIterations / text.length);
    }, speed);

    return () => clearInterval(interval);
  }, [text, speed, maxIterations]);

  return (
    <span className={className}>
      {displayText}
    </span>
  );
};

export default DecryptedText;
