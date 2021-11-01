const darkModeSwitch = document.getElementById("darkModeSwitch");

let isDark = true;
if(localStorage.getItem("dark") === null){
    isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
}else{
    isDark = (localStorage.getItem("dark") === "true");
}

const html = document.querySelector('html');

function updateTheme(){
    localStorage.setItem("dark", isDark);
    darkModeSwitch.checked = isDark;
    if(isDark){
        html.dataset.theme = `theme-dark`;
    }else{
        html.dataset.theme = `theme-light`;
    }
}

updateTheme();

function toggleTheme(){
    isDark = !isDark;
    updateTheme();
}