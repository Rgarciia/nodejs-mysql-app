const express = require('express');
const { redirect, links } = require('express/lib/response');
const res = require('express/lib/response');
const router = express.Router();
const { isLoggedIn } = require('../lib/auth');


const pool = require('../database');
router.get('/add', isLoggedIn, (req, res) => {
    res.render('links/add');
});
router.post('/add', isLoggedIn, async(req, res) => {
    const {title, url, description } = req.body;
    const newLink = {
        title,
        url,
        description,
        user_id: req.user.id
    };
    await  pool.query('INSERT INTO links set ?', [newLink]);
    req.flash('success', 'Link saved successfully');
    res.redirect('/links');
});

router.get('/', isLoggedIn, async (req, res) => {
    const links = await pool.query('SELECT * FROM links WHERE user_id = ?', [req.user.id]);
    console.log(links);
    res.render('links/list.hbs', {links});

});

router.get('/delete/:id', isLoggedIn, async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM links WHERE id = ?', [id]);
    req.flash('success', 'Link removed successfully');
    res.redirect('/links');
});

router.get('/edit/:id', isLoggedIn, async (req, res) => {
    const { id } = req.params;
    const links = await pool.query('SELECT * FROM links WHERE id = ?', [id]);
    res.render('links/edit', {link: links [0]});
});

router.post('/edit/:id', isLoggedIn, async(req, res) => {
    const { id } = req.params;
    const { title, description, url } = req.body;
    const newLink = {
        title,
        description,
        url

    };
    await pool.query('UPDATE links SET ? WHERE id = ?', [newLink, id]);
    req.flash('success', 'Link updated successfully');
    res.redirect('/links');
});



module.exports = router;