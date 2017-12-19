<?php
if (function_exists('login_header')) {
    login_header();
}
?>

<?php if ($error_message) : ?>
    <div id="login_error">
        <?php echo wp_kses($error_message, array('strong' => array())); ?>
    </div>
<?php endif; ?>

<form action="<?php echo esc_url($action_url); ?>" method="post" autocomplete="off">
    <input type="hidden" name="user_id" value="<?php echo absint($user->ID); ?>" />
    <input type="hidden" name="prevent_cc_login_nonce" value="<?php echo esc_attr($_REQUEST['prevent_cc_login_nonce']) ?>" />
    <?php if ($interim_login) { ?>
        <input type="hidden" name="interim-login" value="1" />
    <?php } else { ?>
        <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to) ?>" />
    <?php } ?>

    <p class="warning">
        You are logged in another device. Do you want to force login here?
    </p>
    <p class="submit">
        <label for='cancel'><a class="button button-large" href='<?php echo site_url('wp-login.php'); ?>'><?php esc_attr_e('No'); ?></a></label>
        <input type="submit" id="force_login_prompt" name="force_login_prompt" class="button button-primary button-large" value="<?php esc_attr_e('Yes'); ?>" />
    </p>
</form>

<?php
if (function_exists('login_footer')) {
    login_footer();
}
?>