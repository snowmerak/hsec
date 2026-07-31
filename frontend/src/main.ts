import { mount } from 'svelte'
import "merak-protocol-design-system/style.css"
import "./app.css"
import App from './App.svelte'

mount(App, { target: document.getElementById('app')! })
