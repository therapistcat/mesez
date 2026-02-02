const dontenv = require('dotenv');
const supabase = require('@supabase/supabase-js');
dontenv.config();
const supabaseClient = supabase.createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY,{
    db:{
        schema: 'offthegrid',
    },
});
module.exports = supabaseClient;