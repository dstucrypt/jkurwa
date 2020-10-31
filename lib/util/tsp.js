
const useContentTsp = value => ["all", "content"].includes(value);
const useSignatureTsp = value => ["all", "signature"].includes(value);

module.exports = {useContentTsp, useSignatureTsp};
