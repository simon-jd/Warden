const input=JSON.parse(load('fix5-material-cover-01-pre').initial.output);
const Fixture=Object.getPrototypeOf(async function(){}).constructor;
let result;
try{result=await new Fixture('candidate','mode',input.fixture)(input.candidate,input.mode);}
catch(error){result={fixture_error:String(error),stack:error.stack};}
store('fix5-material-cover-01-result',result);
text(result);
