#include <math.h>

void circle_to_square(float* x, float* y) {
    const float EPSILON = 1e-6f;
    if (!x || !y) return;

    // Clamp input to valid range
    float px = fmaxf(-1.0f, fminf(1.0f, *x));
    float py = fmaxf(-1.0f, fminf(1.0f, *y));

    // Convert to polar coordinates
    float r = sqrtf(px * px + py * py);
    if (r < EPSILON) {
        *x = 0.0f;
        *y = 0.0f;
        return;
    }

    // Calculate angle in radians
    float theta = atan2f(py, px);
    
    // Calculate scaling factor based on angle
    float scale;
    float abs_theta = fabsf(fmodf(theta + M_PI * 0.25f, M_PI * 0.5f) - M_PI * 0.25f);
    if (abs_theta < M_PI * 0.25f) {
        scale = 1.0f / cosf(abs_theta);
    } else {
        scale = 1.0f / sinf(abs_theta);
    }
    
    // Convert back to Cartesian coordinates
    *x = scale * px;
    *y = scale * py;
}