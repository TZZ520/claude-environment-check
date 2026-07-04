import React from 'react';import{createRoot}from'react-dom/client';import App from'./App';import{api}from'./api';import'./style.css';
window.addEventListener('error',e=>{void api.logError(String(e.message||e.error||'unknown error'))});window.addEventListener('unhandledrejection',e=>{void api.logError(String(e.reason||'unhandled rejection'))});
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
