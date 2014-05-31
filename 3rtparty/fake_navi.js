try {
  navigator.appName;
} catch(e) {
  if (typeof(process) !== 'undefined') {
    navigator = {};
  } else {
    throw e;
  }
};

