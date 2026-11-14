const input=JSON.parse(load('material-source-js-input').initial.output);
const Fixture=Object.getPrototypeOf(async function(){}).constructor;
const result=await new Fixture('candidate',input.fixture)(input.candidate);
store('material-source-js-result',result);
text(result);
