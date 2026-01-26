// services/firebase.js
'use strict';

const { db } = require('../config/firebase-admin');

async function get(path) {
  const snap = await db.ref(path).once('value');
  return snap.val();
}

async function set(path, data) {
  await db.ref(path).set(data);
  return true;
}

async function patch(path, data) {
  await db.ref(path).update(data);
  return true;
}

async function remove(path) {
  await db.ref(path).remove();
  return true;
}

module.exports = {
  get,
  set,
  patch,
  remove
};
